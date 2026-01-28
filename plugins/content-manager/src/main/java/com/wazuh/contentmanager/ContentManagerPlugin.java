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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
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
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Supplier;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.engine.services.EngineServiceImpl;
import com.wazuh.contentmanager.jobscheduler.ContentJobParameter;
import com.wazuh.contentmanager.jobscheduler.ContentJobRunner;
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.rest.services.*;
import com.wazuh.contentmanager.settings.PluginSettings;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin
        implements ClusterPlugin, JobSchedulerExtension, ActionPlugin {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private static final String JOB_INDEX_NAME = ".wazuh-content-manager-jobs";
    private static final String JOB_ID = "wazuh-catalog-sync-job";

    private ConsumersIndex consumersIndex;
    private ThreadPool threadPool;
    private CtiConsole ctiConsole;
    private Client client;
    private CatalogSyncJob catalogSyncJob;
    private EngineServiceImpl engine;

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
        this.client = client;
        this.threadPool = threadPool;
        this.consumersIndex = new ConsumersIndex(client);

        // Content Manager 5.0
        this.ctiConsole = new CtiConsole();
        ContentJobRunner runner = ContentJobRunner.getInstance();

        // Initialize CatalogSyncJob
        this.catalogSyncJob =
                new CatalogSyncJob(this.client, this.consumersIndex, environment, this.threadPool);

        // Register Executors
        runner.registerExecutor(CatalogSyncJob.JOB_TYPE, this.catalogSyncJob);

        // Initialize Engine service
        this.engine = new EngineServiceImpl();

        return Collections.emptyList();
    }

    /**
     * Triggers the internal {@link #start()} method if the current node is a Cluster Manager to
     * initialize indices. It also ensures the periodic catalog sync job is scheduled.
     *
     * @param localNode The local node discovery information.
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        // Only cluster managers are responsible for the initialization.
        if (localNode.isClusterManagerNode()) {
            this.start();
        }

        // Schedule the periodic sync job via OpenSearch Job Scheduler
        this.scheduleCatalogSyncJob();

        // Trigger update on start if enabled
        if (PluginSettings.getInstance().isUpdateOnStart()) {
            this.catalogSyncJob.trigger();
        } else {
            log.info("Skipping catalog sync job trigger");
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
            org.opensearch.rest.RestController restController,
            org.opensearch.common.settings.ClusterSettings clusterSettings,
            org.opensearch.common.settings.IndexScopedSettings indexScopedSettings,
            org.opensearch.common.settings.SettingsFilter settingsFilter,
            org.opensearch.cluster.metadata.IndexNameExpressionResolver indexNameExpressionResolver,
            java.util.function.Supplier<org.opensearch.cluster.node.DiscoveryNodes> nodesInCluster) {
        return List.of(
                // CTI subscription endpoints
                new RestGetSubscriptionAction(this.ctiConsole),
                new RestPostSubscriptionAction(this.ctiConsole),
                new RestDeleteSubscriptionAction(this.ctiConsole),
                new RestPostUpdateAction(this.ctiConsole, this.catalogSyncJob),
                // User-generated content endpoints
                new RestPostLogtestAction(this.engine),
                new RestPutPolicyAction(this.engine));
    }

    /** Performs initialization tasks for the plugin. */
    private void start() {
        try {
            this.threadPool
                    .generic()
                    .execute(
                            () -> {
                                try {
                                    CreateIndexResponse response = this.consumersIndex.createIndex();

                                    if (response.isAcknowledged()) {
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
                                }
                            });
        } catch (Exception e) {
            // Log or handle exception
            log.error("Error initializing snapshot helper: {}", e.getMessage(), e);
        }
    }

    /**
     * Schedules the Catalog Sync Job within the OpenSearch Job Scheduler.
     *
     * <p>This method performs two main checks asynchronously:
     *
     * <p>- Ensures the job index ({@value #JOB_INDEX_NAME}) exists. - Ensures the specific job
     * document ({@value #JOB_ID}) exists.
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
                                // 1. Check if the index exists; if not, create it with specific settings.
                                boolean indexExists =
                                        this.client.admin().indices().prepareExists(JOB_INDEX_NAME).get().isExists();

                                if (!indexExists) {
                                    try {
                                        Settings settings =
                                                Settings.builder()
                                                        .put("index.number_of_replicas", 0)
                                                        .put("index.hidden", true)
                                                        .build();

                                        this.client
                                                .admin()
                                                .indices()
                                                .prepareCreate(JOB_INDEX_NAME)
                                                .setSettings(settings)
                                                .get();

                                        log.info("Created job index {}.", JOB_INDEX_NAME);
                                    } catch (Exception e) {
                                        log.warn("Could not create index {}: {}", JOB_INDEX_NAME, e.getMessage());
                                    }
                                }

                                // 2. Check if the job document exists; if not, index it.
                                boolean jobExists = this.client.prepareGet(JOB_INDEX_NAME, JOB_ID).get().isExists();

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
                                            new IndexRequest(JOB_INDEX_NAME)
                                                    .id(JOB_ID)
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
                PluginSettings.CONTENT_CONSUMER);
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
        return JOB_INDEX_NAME;
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
}
