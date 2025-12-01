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


import com.wazuh.contentmanager.cti.catalog.index.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SnapshotManager;
import com.wazuh.contentmanager.cti.catalog.service.SnapshotServiceImpl;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.jobscheduler.ContentJobParameter;
import com.wazuh.contentmanager.jobscheduler.ContentJobRunner;
import com.wazuh.contentmanager.jobscheduler.jobs.HelloWorldJob;
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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Main class of the Content Manager Plugin
 */
public class ContentManagerPlugin extends Plugin implements ClusterPlugin, JobSchedulerExtension, ActionPlugin {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private static final String JOB_INDEX_NAME = ".wazuh-content-manager-jobs";

    /**
     * Semaphore to ensure the context index creation is only triggered once.
     */
    private static final Semaphore indexCreationSemaphore = new Semaphore(1);
    private ConsumersIndex consumersIndex;
    private ThreadPool threadPool;
    private CtiConsole ctiConsole;
    private Client client;
    private Environment environment;

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
        this.client = client;
        ContentJobRunner runner = ContentJobRunner.getInstance();
        runner.registerExecutor(HelloWorldJob.JOB_TYPE, new HelloWorldJob());
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
        this.scheduleHelloWorldJob();

        Runnable scheduledTask = this::job;
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, "Scheduled task"));
        executor.scheduleAtFixedRate(scheduledTask, 30, 30, TimeUnit.SECONDS);
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
            new RestPostUpdateAction(this.ctiConsole)
        );
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
                        if (indexCreationSemaphore.tryAcquire()) {
                            try {
                                CreateIndexResponse response = this.consumersIndex.createIndex();

                                if (response.isAcknowledged()) {
                                    log.info("Index created: {} acknowledged={}", response.index(), response.isAcknowledged());
                                }
                            } catch (Exception e) {
                                log.error("Failed to create {} index, due to: {}", ConsumersIndex.INDEX_NAME, e.getMessage(), e);
                            } finally {
                                indexCreationSemaphore.release();
                            }
                        } else {
                            log.debug("{} index creation already triggered", ConsumersIndex.INDEX_NAME);
                        }
                    });
        } catch (Exception e) {
            // Log or handle exception
            log.error("Error initializing snapshot helper: {}", e.getMessage(), e);
        }
    }


    // Job
    // =========================================================================
    // 1. GetLocalConsumer(consumer): obtain local offset for the given consumer
    //   1.1 If the consumer does not exist, create it.
    // 2. Update
    //   2.1 GetRemoteConsumer(consumer): fetch remote offset for the given consumer
    //   2.2 If local_offset == 0 -> init from snapshot
    //   2.3 If local_offset != remote_offset -> update consumer (changes)
    public void job() {
        this.rulesConsumer();
        this.decodersConsumer();
    }

    /**
     * The ConsumersIndex is unique to the app, as there is only one index.
     * We need as many ContentIndex instances as resources being handled in a given consumer.
     *
     * For each CTI consumer, we need:
     *  - 1x ConsumerService
     *  - 1x SnapshotService
     *  - As many of indices as needed by the CTI consumer. In this case, 2: rules, integrations
     */
    private void rulesConsumer() {
        String context = "rules_development_0.0.1";
        String consumer = "rules_development_0.0.1_test";
        Map<String, String> mappings = new HashMap<>();
        mappings.put(
            "rule", "/mappings/cti-rules-mappings.json"
        );
        mappings.put(
            "integration", "/mappings/cti-rules-integrations-mappings.json"
        );
        this.initConsumerServices(context, consumer, mappings);
    }

    /**
     * The ConsumersIndex is unique to the app, as there is only one index.
     * We need as many ContentIndex instances as resources being handled in a given consumer.
     *
     * For each CTI consumer, we need:
     *  - 1x ConsumerService
     *  - 1x SnapshotService
     *  - As many of indices as needed by the CTI consumer. In this case, 2: rules, integrations
     */
    private void decodersConsumer() {
        String context = "decoders_development_0.0.1";
        String consumer = "decoders_development_0.0.1";
        Map<String, String> mappings = new HashMap<>();
        mappings.put(
            "decoder", "/mappings/cti-decoders-mappings.json"
        );
        mappings.put(
            "kvdb", "/mappings/cti-kvdbs-mappings.json"
        );
        mappings.put(
            "integration", "/mappings/cti-decoders-integrations-mappings.json"
        );
       this.initConsumerServices(context, consumer, mappings);
    }

    private String getIndexName(String context, String consumer, String type) {
        return String.format(
            Locale.ROOT, ".%s-%s-%s",
            context,
            consumer,
            type
        );
    }

    private void initConsumerServices(String context, String consumer, Map<String, String> mappings) {
        ConsumerService consumerService = new ConsumerServiceImpl(context, consumer, this.consumersIndex);
        LocalConsumer localConsumer = consumerService.getLocalConsumer();
        RemoteConsumer remoteConsumer = consumerService.getRemoteConsumer();

        log.info("Local consumer: {}", localConsumer);
        log.info("Remote consumer: {}", remoteConsumer);

        List<ContentIndex> indices = new ArrayList<>();
        for (Map.Entry<String, String> entry : mappings.entrySet()) {
            // Add to the list of indices for the SnapshotService
            String indexName = this.getIndexName(context, consumer, entry.getKey());
            ContentIndex index = new ContentIndex(this.client, indexName, entry.getValue());
            indices.add(index);

            // Create index
            try {
                CreateIndexResponse response = index.createIndex();
                if (response.isAcknowledged()) {
                    log.info("Index [{}] created successfully", response.index());
                }
            } catch (Exception e) {
                log.error("Failed to create index [{}]: {}", indexName, e.getMessage());
            }
        }

        // Initialize snapshot if available
        if (remoteConsumer.getSnapshotLink() != null && localConsumer.getLocalOffset() == 0 ){
            log.info("Initializing snapshot from link: {}", remoteConsumer.getSnapshotLink());
            SnapshotServiceImpl snapshotService = new SnapshotServiceImpl(
                context,
                consumer,
                indices,
                this.consumersIndex,
                this.environment
            );
            snapshotService.initialize(remoteConsumer);
        }
        else{
            log.info("Indices already initialized. ");
        }
    }

    // TODO: Change to actual job implementation, this is just an example
    private void scheduleHelloWorldJob() {
        String jobId = "wazuh-hello-world-job";
        this.threadPool.generic().execute(() -> {
            try {
                boolean exists = this.client.admin().indices().prepareExists(JOB_INDEX_NAME).get().isExists() &&
                    this.client.prepareGet(JOB_INDEX_NAME, jobId).get().isExists();
                if (!exists) {
                    log.info("Scheduling Hello World Job to run every 1 minute...");
                    ContentJobParameter job = new ContentJobParameter(
                        "Hello World Periodic Task",
                        HelloWorldJob.JOB_TYPE,
                        new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES),
                        true,
                        Instant.now(),
                        Instant.now()
                    );
                    IndexRequest request = new IndexRequest(JOB_INDEX_NAME)
                        .id(jobId)
                        .source(job.toXContent(XContentFactory.jsonBuilder(), null));
                    this.client.index(request).actionGet();
                    log.info("Hello World Job scheduled successfully.");
                }
            } catch (Exception e) {
                log.error("Error scheduling Hello World Job: {}", e.getMessage());
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
