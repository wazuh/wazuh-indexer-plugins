/*
 * Copyright (C) 2024, Wazuh Inc.
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

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.jobscheduler.ContentJobParameter;
import com.wazuh.contentmanager.jobscheduler.ContentJobRunner;
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.rest.services.RestDeleteSubscriptionAction;
import com.wazuh.contentmanager.rest.services.RestGetSubscriptionAction;
import com.wazuh.contentmanager.rest.services.RestPostSubscriptionAction;
import com.wazuh.contentmanager.rest.services.RestPostUpdateAction;
import com.wazuh.contentmanager.settings.PluginSettings;
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

/**
 * Main class of the Content Manager Plugin
 */
public class ContentManagerPlugin extends Plugin implements ClusterPlugin, JobSchedulerExtension, ActionPlugin {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private static final String JOB_INDEX_NAME = ".wazuh-content-manager-jobs";
    private static final String JOB_ID = "wazuh-catalog-sync-job";

    private ConsumersIndex consumersIndex;
    private ThreadPool threadPool;
    private CtiConsole ctiConsole;
    private Client client;
    private Environment environment;
    private CatalogSyncJob catalogSyncJob;

    // Rest API endpoints
    public static final String PLUGINS_BASE_URI = "/_plugins/content-manager";
    public static final String SUBSCRIPTION_URI = PLUGINS_BASE_URI + "/subscription";
    public static final String UPDATE_URI = PLUGINS_BASE_URI + "/update";

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
        PluginSettings.getInstance(environment.settings(), clusterService);
        this.client = client;
        this.threadPool = threadPool;
        this.environment = environment;
        this.consumersIndex = new ConsumersIndex(client);

        // Content Manager 5.0
        this.ctiConsole = new CtiConsole();
        ContentJobRunner runner = ContentJobRunner.getInstance();

        // Initialize CatalogSyncJob
        this.catalogSyncJob = new CatalogSyncJob(client, consumersIndex, environment, threadPool);

        // Register Executors
        runner.registerExecutor(CatalogSyncJob.JOB_TYPE, this.catalogSyncJob);

        return Collections.emptyList();
    }

    /**
     * The initialization requires the existence of the {@link ContentIndex#INDEX_NAME} index. For
     * this reason, we use a ClusterStateListener to listen for the creation of this index by the
     * "setup" plugin, to then proceed with the initialization.
     *
     * @param localNode local Node info
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        // Only cluster managers are responsible for the initialization.
        if (localNode.isClusterManagerNode()) {
            this.start();
        }

        // Schedule the periodic sync job via OpenSearch Job Scheduler
        this.scheduleCatalogSyncJob();
    }

    public List<RestHandler> getRestHandlers(
        Settings settings,
        org.opensearch.rest.RestController restController,
        org.opensearch.common.settings.ClusterSettings clusterSettings,
        org.opensearch.common.settings.IndexScopedSettings indexScopedSettings,
        org.opensearch.common.settings.SettingsFilter settingsFilter,
        org.opensearch.cluster.metadata.IndexNameExpressionResolver indexNameExpressionResolver,
        java.util.function.Supplier<org.opensearch.cluster.node.DiscoveryNodes> nodesInCluster) {
        return List.of(
            new RestGetSubscriptionAction(this.ctiConsole),
            new RestPostSubscriptionAction(this.ctiConsole),
            new RestDeleteSubscriptionAction(this.ctiConsole),
            new RestPostUpdateAction(this.ctiConsole, this.catalogSyncJob));
    }

    /**
     * Initialize. The initialization consists of:
     *
     * <pre>
     * 1. create required indices if they do not exist.
     * 2. initialize from a snapshot if the local consumer does not exist, or its offset is 0.
     * </pre>
     */
    private void start() {
        try {
            this.threadPool
                .generic()
                .execute(
                    () -> {
                        try {
                            CreateIndexResponse response = this.consumersIndex.createIndex();

                            if (response.isAcknowledged()) {
                                log.info("Index created: {} acknowledged={}", response.index(), response.isAcknowledged());
                            }
                        } catch (Exception e) {
                            log.error("Failed to create {} index, due to: {}", ConsumersIndex.INDEX_NAME, e.getMessage(), e);
                        }
                    });
        } catch (Exception e) {
            // Log or handle exception
            log.error("Error initializing snapshot helper: {}", e.getMessage(), e);
        }
    }


    /**
     * Schedules the Catalog Sync Job.
     */
    private void scheduleCatalogSyncJob() {
        this.threadPool.generic().execute(() -> {
            try {
                // 1. Check if the index exists; if not, create it with specific settings.
                boolean indexExists = this.client.admin().indices().prepareExists(JOB_INDEX_NAME).get().isExists();

                if (!indexExists) {
                    try {
                        Settings settings = Settings.builder()
                            .put("index.number_of_replicas", 0)
                            .put("index.hidden", true)
                            .build();

                        this.client.admin().indices().prepareCreate(JOB_INDEX_NAME)
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
                    ContentJobParameter job = new ContentJobParameter(
                        "Catalog Sync Periodic Task",
                        CatalogSyncJob.JOB_TYPE,
                        new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES),
                        true,
                        Instant.now(),
                        Instant.now()
                    );
                    IndexRequest request = new IndexRequest(JOB_INDEX_NAME)
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

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
            PluginSettings.CONSUMER_ID,
            PluginSettings.CONTEXT_ID,
            PluginSettings.CLIENT_TIMEOUT,
            PluginSettings.CTI_API_URL,
            PluginSettings.CTI_CLIENT_MAX_ATTEMPTS,
            PluginSettings.CTI_CLIENT_SLEEP_TIME,
            PluginSettings.JOB_MAX_DOCS,
            PluginSettings.JOB_SCHEDULE,
            PluginSettings.MAX_CHANGES,
            PluginSettings.MAX_CONCURRENT_BULKS,
            PluginSettings.MAX_ITEMS_PER_BULK);
    }

    @Override
    public String getJobType() {
        return "content-manager-job";
    }

    @Override
    public String getJobIndex() {
        return JOB_INDEX_NAME;
    }

    @Override
    public ScheduledJobRunner getJobRunner() {
        return ContentJobRunner.getInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
        return (parser, id, jobDocVersion) -> ContentJobParameter.parse(parser);
    }
}
