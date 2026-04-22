/*
 * Copyright (C) 2024-2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
import org.opensearch.jobscheduler.spi.ScheduledJobParser;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.LogtestService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.engine.service.EngineServiceImpl;
import com.wazuh.contentmanager.jobscheduler.ContentJobParameter;
import com.wazuh.contentmanager.jobscheduler.ContentJobRunner;
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.jobscheduler.jobs.TelemetryPingJob;
import com.wazuh.contentmanager.rest.service.*;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;
import com.wazuh.contentmanager.utils.MockEngineService;
import com.wazuh.contentmanager.utils.MockSecurityAnalyticsService;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin
        implements ClusterPlugin, JobSchedulerExtension, ActionPlugin {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private static final String CONTENT_MANAGER_JOBS_INDEX_NAME = ".wazuh-content-manager-jobs";
    private static final String CATALOG_SYNC_JOB_ID = "wazuh-catalog-sync-job";
    private static final String TELEMETRY_JOB_ID = "wazuh-telemetry-ping-job";
    private static final String VERSION_FILE_NAME = "VERSION.json";
    private static final String VERSION_SYSTEM_PROPERTY = "wazuh.version";

    private ConsumersIndex consumersIndex;
    private ThreadPool threadPool;
    private CtiConsole ctiConsole;
    private Client client;
    private CatalogSyncJob catalogSyncJob;
    private TelemetryPingJob telemetryPingJob;
    private EngineService engine;
    private SpaceService spaceService;
    private SecurityAnalyticsService securityAnalyticsService;
    private Environment environment;
    private ClusterService clusterService;
    private LogtestService logtestService;

    /**
     * Initializes the plugin components, including the CTI console, consumer index helpers, and the
     * catalog synchronization job.
     *
     * @param client The OpenSearch client.
     * @param clusterService The cluster service for managing cluster state.
     * @param threadPool The thread pool for executing asynchronous tasks.
     * @param resourceWatcherService Service for watching resource changes.
     * @param scriptService Service for executing scripts.
     * @param xContentRegistry Registry for XContent parsers.
     * @param environment The node environment settings.
     * @param nodeEnvironment The node environment information.
     * @param namedWriteableRegistry Registry for named writeables.
     * @param indexNameExpressionResolver Resolver for index name expressions.
     * @param repositoriesServiceSupplier Supplier for the repositories service.
     * @return A collection of constructed components (empty in this implementation as components are
     *     stored internally).
     */
    @Override
    public Collection<Object> createComponents(
            Client client,
            ClusterService clusterService,
            ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService,
            ScriptService scriptService,
            NamedXContentRegistry xContentRegistry,
            Environment environment,
            NodeEnvironment nodeEnvironment,
            NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<RepositoriesService> repositoriesServiceSupplier) {
        PluginSettings.getInstance(environment.settings());
        this.environment = environment;
        this.clusterService = clusterService;
        this.client = client;
        this.threadPool = threadPool;
        this.consumersIndex = new ConsumersIndex(client);

        // Content Manager 5.0
        this.ctiConsole = new CtiConsole();
        ContentJobRunner runner = ContentJobRunner.getInstance();

        // Initialize Engine service
        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            this.engine = new MockEngineService();
        } else {
            this.engine = new EngineServiceImpl();
        }

        // Initialize CatalogSyncJob
        this.catalogSyncJob =
                new CatalogSyncJob(
                        this.client, this.consumersIndex, environment, this.threadPool, this.engine);

        // Initialize TelemetryPingJob
        this.telemetryPingJob =
                new TelemetryPingJob(environment.settings(), clusterService, threadPool, environment);

        // Register Executors
        runner.registerExecutor(CatalogSyncJob.JOB_TYPE, this.catalogSyncJob);
        runner.registerExecutor(TelemetryPingJob.JOB_TYPE, this.telemetryPingJob);

        // Initialize services
        this.spaceService = new SpaceService(this.client);
        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            this.securityAnalyticsService = new MockSecurityAnalyticsService();
        } else {
            this.securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        }

        this.logtestService =
                new LogtestService(this.engine, this.securityAnalyticsService, this.client);

        // Register hot-reload settings consumer
        clusterService
                .getClusterSettings()
                .addSettingsUpdateConsumer(
                        PluginSettings.TELEMETRY_ENABLED, this::onTelemetrySettingChanged);

        return Collections.emptyList();
    }

    /**
     * Triggers the internal {@link #start(Runnable)} method if the current node is a Cluster Manager
     * to initialize indices. It also ensures the periodic catalog sync job is scheduled.
     *
     * <p>The startup sync trigger is restricted to the cluster manager node to prevent every node in
     * the cluster from running a concurrent synchronization on startup.
     *
     * @param localNode The local node discovery information.
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        // Only cluster managers are responsible for initialization and the startup sync trigger.
        if (localNode.isClusterManagerNode()) {
            this.start(
                    () -> {
                        // Trigger update on start if enabled
                        if (PluginSettings.getInstance().isUpdateOnStart()) {
                            this.catalogSyncJob.trigger();
                        } else {
                            log.info("Skipping catalog sync job trigger");
                        }

                        // Schedule the periodic sync job via OpenSearch Job Scheduler (all nodes)
                        this.scheduleCatalogSyncJob();
                        // Schedule the telemetry ping job
                        this.scheduleTelemetryPingJob();
                    });
        }
    }

    /**
     * Registers the REST handlers for the Content Manager API.
     *
     * @param settings The node settings.
     * @param restController The REST controller.
     * @param clusterSettings The cluster settings.
     * @param indexScopedSettings The index scoped settings.
     * @param settingsFilter The settings filter.
     * @param indexNameExpressionResolver The index name resolver.
     * @param nodesInCluster Supplier for nodes in the cluster.
     * @return A list of REST handlers.
     */
    @Override
    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster) {
        return List.of(
                // CTI subscription endpoints
                new RestGetSubscriptionAction(this.ctiConsole),
                new RestPostSubscriptionAction(this.ctiConsole),
                new RestDeleteSubscriptionAction(this.ctiConsole),
                new RestPostUpdateAction(this.ctiConsole, this.catalogSyncJob),
                // Version check endpoint
                new RestGetVersionCheckAction(this.environment, this.clusterService),
                // User-generated content endpoints
                new RestPostLogtestAction(this.logtestService),
                new RestPostLogtestNormalizationAction(this.logtestService),
                new RestPostLogtestDetectionAction(this.logtestService),
                // Policy endpoints
                new RestPutPolicyAction(this.spaceService, this.engine),
                // Rule endpoints
                new RestPostRuleAction(),
                new RestPutRuleAction(),
                new RestDeleteRuleAction(),
                // Integration endpoints
                new RestPostIntegrationAction(this.engine),
                new RestPutIntegrationAction(this.engine),
                new RestDeleteIntegrationAction(this.engine),
                // Decoder endpoints
                new RestPostDecoderAction(this.engine),
                new RestPutDecoderAction(this.engine),
                new RestDeleteDecoderAction(this.engine),
                // KVDB endpoints
                new RestPostKvdbAction(this.engine),
                new RestPutKvdbAction(this.engine),
                new RestDeleteKvdbAction(this.engine),
                // Promote endpoints
                new RestPostPromoteAction(this.engine, this.spaceService, this.securityAnalyticsService),
                new RestGetPromoteAction(this.spaceService),
                // Engine Filters endpoints
                new RestPostFilterAction(this.engine),
                new RestPutFilterAction(this.engine),
                new RestDeleteFilterAction(this.engine),
                // Space deletion endpoint
                new RestDeleteSpaceAction());
    }

    /**
     * Performs initialization tasks for the plugin. Creates the consumers index asynchronously and
     * invokes the provided callback once the operation completes (whether it succeeds or fails).
     *
     * @param onComplete callback to run after index creation completes
     */
    private void start(Runnable onComplete) {
        try {
            this.threadPool
                    .generic()
                    .execute(
                            () -> {
                                try {
                                    CreateIndexResponse response = this.consumersIndex.createIndex();

                                    if (response != null && response.isAcknowledged()) {
                                        log.info(
                                                "Index created: {} acknowledged={}",
                                                response.index(),
                                                response.isAcknowledged());
                                    }
                                } catch (Exception e) {
                                    log.error(
                                            "Failed to create {} index, due to: {}",
                                            ConsumersIndex.INDEX_NAME,
                                            e.getMessage(),
                                            e);
                                } finally {
                                    onComplete.run();
                                }
                            });
        } catch (Exception e) {
            log.error("Error initializing snapshot helper: {}", e.getMessage(), e);
            onComplete.run();
        }
    }

    /** Check if the index exists; if not, create it with specific settings. */
    private void ensureJobsIndexExists() {
        if (!ClusterInfo.indexExists(this.client, CONTENT_MANAGER_JOBS_INDEX_NAME)) {
            try {
                Settings settings =
                        Settings.builder().put("index.number_of_replicas", 0).put("index.hidden", true).build();

                this.client
                        .admin()
                        .indices()
                        .prepareCreate(CONTENT_MANAGER_JOBS_INDEX_NAME)
                        .setSettings(settings)
                        .get();

                log.info("Created job index {}.", CONTENT_MANAGER_JOBS_INDEX_NAME);
            } catch (ResourceAlreadyExistsException e) {
                log.debug("Index {} already exists. Skipping.", CONTENT_MANAGER_JOBS_INDEX_NAME);
            } catch (Exception e) {
                log.warn("Could not create index {}: {}", CONTENT_MANAGER_JOBS_INDEX_NAME, e.getMessage());
            }
        }

        // Wait for at least yellow status with active shards ready for operations.
        if (!ClusterInfo.indexStatusCheck(
                this.client,
                CONTENT_MANAGER_JOBS_INDEX_NAME,
                PluginSettings.getInstance().getClientTimeout())) {
            throw new RuntimeException("Index " + CONTENT_MANAGER_JOBS_INDEX_NAME + " not ready");
        }
    }

    /**
     * Schedules the Catalog Sync Job within the OpenSearch Job Scheduler.
     *
     * <p>This method performs two main checks asynchronously:
     *
     * <p>- Ensures the job index ({@value #CONTENT_MANAGER_JOBS_INDEX_NAME}) exists. - Ensures the
     * specific job document ({@value #CATALOG_SYNC_JOB_ID}) exists.
     *
     * <p>If either is missing, it creates them. The job is configured to run based on the interval
     * defined in PluginSettings.
     */
    private void scheduleCatalogSyncJob() {
        this.threadPool
                .generic()
                .execute(
                        () -> {
                            try {
                                this.ensureJobsIndexExists();

                                // 2. Check if the job document exists; if not, index it.
                                boolean jobExists =
                                        this.client
                                                .prepareGet(CONTENT_MANAGER_JOBS_INDEX_NAME, CATALOG_SYNC_JOB_ID)
                                                .get()
                                                .isExists();

                                if (!jobExists) {
                                    ContentJobParameter job =
                                            new ContentJobParameter(
                                                    "Catalog Sync Periodic Task",
                                                    CatalogSyncJob.JOB_TYPE,
                                                    new IntervalSchedule(
                                                            Instant.now(),
                                                            PluginSettings.getInstance().getCatalogSyncInterval(),
                                                            ChronoUnit.MINUTES),
                                                    PluginSettings.getInstance().isUpdateOnSchedule(),
                                                    Instant.now(),
                                                    Instant.now());
                                    IndexRequest request =
                                            new IndexRequest(CONTENT_MANAGER_JOBS_INDEX_NAME)
                                                    .id(CATALOG_SYNC_JOB_ID)
                                                    .source(job.toXContent(XContentFactory.jsonBuilder(), null));
                                    this.client.index(request).actionGet();
                                    log.info("Catalog Sync Job scheduled successfully.");
                                }
                            } catch (Exception e) {
                                log.error("Error scheduling Catalog Sync Job: {}", e.getMessage());
                            }
                        });
    }

    /**
     * Schedules the Telemetry Ping Job within the OpenSearch Job Scheduler. * This method ensures
     * that the telemetry heartbeat is registered in the internal job index. If the job document does
     * not exist, it creates a new one with a 24-hour interval and fires an immediate ping once
     * registration succeeds. If the document already exists, the scheduler owns subsequent fires.
     */
    private void scheduleTelemetryPingJob() {
        boolean isEnabled = PluginSettings.getInstance().isTelemetryEnabled();
        if (!isEnabled) {
            log.info("Telemetry job is disabled via settings. Skipping registration.");
            return;
        }

        this.threadPool
                .generic()
                .execute(
                        () -> {
                            try {
                                this.ensureJobsIndexExists();

                                // Ensure cluster is operational.
                                ClusterHealthStatus status =
                                        this.client
                                                .admin()
                                                .cluster()
                                                .prepareHealth()
                                                .setWaitForGreenStatus()
                                                .get()
                                                .getStatus();
                                if (status == ClusterHealthStatus.RED) {
                                    log.info("Telemetry job is enabled, but cluster is RED. Skipping registration.");
                                }

                                boolean jobExists =
                                        this.client
                                                .prepareGet(CONTENT_MANAGER_JOBS_INDEX_NAME, TELEMETRY_JOB_ID)
                                                .get()
                                                .isExists();

                                if (!jobExists) {
                                    ContentJobParameter job =
                                            new ContentJobParameter(
                                                    "Telemetry Ping Periodic Task",
                                                    TelemetryPingJob.JOB_TYPE,
                                                    new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS),
                                                    true,
                                                    Instant.now(),
                                                    Instant.now());

                                    IndexRequest request =
                                            new IndexRequest(CONTENT_MANAGER_JOBS_INDEX_NAME)
                                                    .id(TELEMETRY_JOB_ID)
                                                    .source(job.toXContent(XContentFactory.jsonBuilder(), null));

                                    this.client.index(request).actionGet();
                                    log.info("Telemetry Ping Job scheduled successfully (Interval: 1d).");

                                    // Run the first ping immediately; subsequent fires are owned by
                                    // the Job Scheduler on the 1-day interval.
                                    if (this.telemetryPingJob != null) {
                                        this.telemetryPingJob.trigger();
                                    }
                                }
                            } catch (Exception e) {
                                log.error("Failed to schedule Telemetry Ping Job: {}", e.getMessage());
                            }
                        });
    }

    /** Handles the dynamic setting change for telemetry */
    private void onTelemetrySettingChanged(boolean isEnabled) {
        PluginSettings.getInstance().setTelemetryEnabled(isEnabled);
        if (isEnabled) {
            log.info(
                    "Telemetry setting dynamically enabled. Scheduling job and triggering initial run...");
            this.scheduleTelemetryPingJob();
        } else {
            log.info("Telemetry setting dynamically disabled. Removing job...");
            this.removeTelemetryPingJob();
        }
    }

    /** Removes the Telemetry Ping Job from the Job Scheduler */
    private void removeTelemetryPingJob() {
        this.threadPool
                .generic()
                .execute(
                        () -> {
                            try {
                                boolean indexExists =
                                        this.client
                                                .admin()
                                                .indices()
                                                .prepareExists(CONTENT_MANAGER_JOBS_INDEX_NAME)
                                                .get()
                                                .isExists();

                                if (indexExists) {
                                    boolean jobExists =
                                            this.client
                                                    .prepareGet(CONTENT_MANAGER_JOBS_INDEX_NAME, TELEMETRY_JOB_ID)
                                                    .get()
                                                    .isExists();
                                    if (jobExists) {
                                        this.client
                                                .prepareDelete(CONTENT_MANAGER_JOBS_INDEX_NAME, TELEMETRY_JOB_ID)
                                                .get();
                                        log.info("Telemetry Ping Job removed successfully.");
                                    }
                                }
                            } catch (Exception e) {
                                log.error("Failed to remove Telemetry Ping Job: {}", e.getMessage());
                            }
                        });
    }

    /**
     * Retrieves the list of settings defined by this plugin.
     *
     * @return A list of {@link Setting} objects including client timeout, API URL, bulk operation
     *     limits, and sync interval.
     */
    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
                PluginSettings.CLIENT_TIMEOUT,
                PluginSettings.CTI_API_URL,
                PluginSettings.MAX_CONCURRENT_BULKS,
                PluginSettings.MAX_ITEMS_PER_BULK,
                PluginSettings.CATALOG_SYNC_INTERVAL,
                PluginSettings.UPDATE_ON_START,
                PluginSettings.UPDATE_ON_SCHEDULE,
                PluginSettings.CONTENT_CONTEXT,
                PluginSettings.CONTENT_CONSUMER,
                PluginSettings.IOC_CONTEXT,
                PluginSettings.IOC_CONSUMER,
                PluginSettings.TELEMETRY_ENABLED,
                PluginSettings.CVE_CONTEXT,
                PluginSettings.CVE_CONSUMER,
                PluginSettings.PIT_KEEPALIVE,
                PluginSettings.ENGINE_MOCK_ENABLED,
                PluginSettings.CREATE_DETECTORS);
    }

    /**
     * Returns the job type identifier for the Job Scheduler extension.
     *
     * @return The string identifier for content manager jobs.
     */
    @Override
    public String getJobType() {
        return "content-manager-job";
    }

    /**
     * Returns the name of the index used to store job metadata.
     *
     * @return The job index name.
     */
    @Override
    public String getJobIndex() {
        return CONTENT_MANAGER_JOBS_INDEX_NAME;
    }

    /** Returns the runner instance responsible for executing the scheduled jobs. */
    @Override
    public ScheduledJobRunner getJobRunner() {
        return ContentJobRunner.getInstance();
    }

    /**
     * Returns the parser responsible for deserializing job parameters from XContent.
     *
     * @return A {@link ScheduledJobParser} for {@link ContentJobParameter}.
     */
    @Override
    public ScheduledJobParser getJobParser() {
        return (parser, id, jobDocVersion) -> ContentJobParameter.parse(parser);
    }

    /**
     * Returns the version of Wazuh. The version is stored in the
     * '/usr/share/wazuh-indexerVERSION.json' file.
     *
     * @param env Environment instance to access the filesystem.
     * @return the Wazuh version as string. Null if it cannot be read from the file or if the
     *     'version' field is missing/empty.
     */
    public static String getVersion(Environment env) {
        String pathHome = env.settings().get("path.home", "/usr/share/wazuh-indexer");
        Path versionFilePath = Path.of(pathHome, VERSION_FILE_NAME);
        try {
            String fileVersion =
                    AccessController.doPrivilegedChecked(
                            () -> {
                                String content = Files.readString(versionFilePath, StandardCharsets.UTF_8);
                                JsonNode json = new ObjectMapper().readTree(content);
                                JsonNode versionNode = json.get("version");
                                return versionNode != null ? versionNode.asText() : null;
                            });

            if (fileVersion != null && !fileVersion.isBlank()) {
                return fileVersion;
            }

            log.warn("VERSION.json found but 'version' field is empty or missing.");
        } catch (Exception e) {
            log.warn("Could not read VERSION.json: {}", e.getMessage());
        }

        String configuredVersion = System.getProperty(VERSION_SYSTEM_PROPERTY);
        if (configuredVersion != null && !configuredVersion.isBlank()) {
            return configuredVersion;
        }

        return null;
    }
}
