package com.wazuh.contentmanager.jobscheduler.jobs;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SnapshotServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.UpdateServiceImpl;
import com.wazuh.contentmanager.jobscheduler.JobExecutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Semaphore;

/**
 * Job responsible for executing the synchronization logic for Rules and Decoders consumers.
 */
public class CatalogSyncJob implements JobExecutor {
    private static final Logger log = LogManager.getLogger(CatalogSyncJob.class);

    // Identifier used to route this specific job type
    public static final String JOB_TYPE = "consumer-sync-task";

    // Semaphore to control concurrency
    private final Semaphore semaphore = new Semaphore(1);

    private final Client client;
    private final ConsumersIndex consumersIndex;
    private final Environment environment;
    private final ThreadPool threadPool;

    /**
     * Constructs a new CatalogSyncJob.
     *
     * @param client         The OpenSearch client used for administrative index operations (create/check).
     * @param consumersIndex The wrapper for accessing and managing the internal Consumers index.
     * @param environment    The OpenSearch environment settings, used for path resolution.
     * @param threadPool     The thread pool manager, used to offload blocking tasks to the generic executor.
     */
    public CatalogSyncJob(Client client, ConsumersIndex consumersIndex, Environment environment, ThreadPool threadPool) {
        this.client = client;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
        this.threadPool = threadPool;
    }

    /**
     * Triggers the execution of the synchronization job via the Job Scheduler.
     *
     * @param context The execution context provided by the Job Scheduler, containing metadata like the Job ID.
     */
    @Override
    public void execute(JobExecutionContext context) {
        if (!this.semaphore.tryAcquire()) {
            log.warn("CatalogSyncJob (ID: {}) skipped because synchronization is already running.", context.getJobId());
            return;
        }

        // Offload execution to the generic thread pool to allow blocking operations
        this.threadPool.generic().execute(() -> {
            try {
                log.info("Executing Consumer Sync Job (ID: {})", context.getJobId());
                this.performSynchronization();
            } catch (Exception e) {
                log.error("Error executing Consumer Sync Job (ID: {}): {}", context.getJobId(), e.getMessage(), e);
            } finally {
                this.semaphore.release();
            }
        });
    }

    /**
     * Checks if the synchronization job is currently running.
     *
     * @return true if running, false otherwise.
     */
    public boolean isRunning() {
        return this.semaphore.availablePermits() == 0;
    }

    /**
     * Attempts to trigger the synchronization process manually.
     *
     * @return true if the job was successfully started, false if it is already running.
     */
    public boolean trigger() {
        if (!this.semaphore.tryAcquire()) {
            log.warn("Attempted to trigger CatalogSyncJob manually while it is already running.");
            return false;
        }
        this.threadPool.generic().execute(() -> {
            try {
                log.info("Executing Manually Triggered Consumer Sync Job");
                this.performSynchronization();
            } catch (Exception e) {
                log.error("Error executing Manual Consumer Sync Job: {}", e.getMessage(), e);
            } finally {
                this.semaphore.release();
            }
        });

        return true;
    }

    /**
     * Centralized synchronization logic used by both execute() and trigger().
     */
    private void performSynchronization() {
        this.rulesConsumer();
        this.decodersConsumer();
    }

    /**
     * Orchestrates the synchronization process specifically for the Rules consumer.
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

        Map<String, String> aliases = new HashMap<>();
        aliases.put("rule", ".cti-rules");
        aliases.put("integration", ".cti-integration-rules");

        this.syncConsumerServices(context, consumer, mappings, aliases);
        log.info("Rules Consumer correctly synchronized.");
    }

    /**
     * Orchestrates the synchronization process specifically for the Decoders consumer.
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

        Map<String, String> aliases = new HashMap<>();
        aliases.put("decoder", ".cti-decoders");
        aliases.put("kvdb", ".cti-kvdbs");
        aliases.put("integration", ".cti-integration-decoders");

        this.syncConsumerServices(context, consumer, mappings, aliases);
        log.info("Decoders Consumer correctly synchronized.");
    }

    /**
     * Generates a standardized OpenSearch index name based on the provided parameters.
     *
     * @param context  The context identifier (e.g., version info).
     * @param consumer The consumer identifier.
     * @param type     The specific content type (e.g., "rule", "decoder").
     * @return A formatted string representing the system index name.
     */
    private String getIndexName(String context, String consumer, String type) {
        return String.format(
            Locale.ROOT, ".%s-%s-%s",
            context,
            consumer,
            type
        );
    }

    /**
     * The core logic for synchronizing consumer services.
     *
     * This method performs the following actions:
     * 1. Retrieve the Local and Remote consumer metadata.
     * 2. Iterate through the requested mappings to check if indices exist.
     * 3. Create indices using the provided mapping files if they are missing.
     * 4. Compare local offsets with remote offsets to determine if a Snapshot initialization is required.
     * 5. Triggers a full snapshot download if the local consumer is new or empty.
     * 6. Triggers the update process if the offsets from local and remote consumers differ.
     *
     * @param context  The versioned context string.
     * @param consumer The specific consumer identifier.
     * @param mappings A map associating content types to their JSON mapping file paths.
     * @param aliases  A map associating content types to their OpenSearch alias names.
     */
    private void syncConsumerServices(String context, String consumer, Map<String, String> mappings, Map<String, String> aliases) {
        ConsumerService consumerService = new ConsumerServiceImpl(context, consumer, this.consumersIndex);
        LocalConsumer localConsumer = consumerService.getLocalConsumer();
        RemoteConsumer remoteConsumer = consumerService.getRemoteConsumer();

        List<ContentIndex> indices = new ArrayList<>();
        Map<String, ContentIndex> indicesMap = new HashMap<>();

        for (Map.Entry<String, String> entry : mappings.entrySet()) {
            String indexName = this.getIndexName(context, consumer, entry.getKey());
            String alias = aliases.get(entry.getKey());
            ContentIndex index = new ContentIndex(this.client, indexName, entry.getValue(), alias);
            indices.add(index);
            indicesMap.put(entry.getKey(), index);

            // Check if index exists to avoid creation exception
            boolean indexExists = this.client.admin().indices().prepareExists(indexName).get().isExists();

            if (!indexExists) {
                try {
                    CreateIndexResponse response = index.createIndex();
                    if (response.isAcknowledged()) {
                        log.info("Index [{}] created successfully", response.index());
                    }
                } catch (Exception e) {
                    log.error("Failed to create index [{}]: {}", indexName, e.getMessage());
                }
            }
        }

        if (remoteConsumer != null && remoteConsumer.getSnapshotLink() != null && (localConsumer == null || localConsumer.getLocalOffset() == 0)) {
            log.info("Initializing snapshot from link: {}", remoteConsumer.getSnapshotLink());
            SnapshotServiceImpl snapshotService = new SnapshotServiceImpl(
                context,
                consumer,
                indices,
                this.consumersIndex,
                this.environment
            );
            snapshotService.initialize(remoteConsumer);
        } else if (remoteConsumer != null && localConsumer.getLocalOffset() != remoteConsumer.getOffset()) {
            log.info("Starting offset-based update for consumer [{}]", consumer);
            UpdateServiceImpl updateService = new UpdateServiceImpl(
                context,
                consumer,
                new ApiClient(),
                this.consumersIndex,
                indicesMap
            );
            updateService.update(localConsumer.getLocalOffset(), remoteConsumer.getOffset());
            updateService.close();
        }
    }
}
