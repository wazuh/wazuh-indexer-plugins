package com.wazuh.contentmanager.jobscheduler.jobs;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SnapshotServiceImpl;
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

/**
 * Job responsible for executing the synchronization logic for Rules and Decoders consumers.
 */
public class CatalogSyncJob implements JobExecutor {
    private static final Logger log = LogManager.getLogger(CatalogSyncJob.class);

    // Identifier used to route this specific job type
    public static final String JOB_TYPE = "consumer-sync-task";

    private final Client client;
    private final ConsumersIndex consumersIndex;
    private final Environment environment;
    private final ThreadPool threadPool;

    public CatalogSyncJob(Client client, ConsumersIndex consumersIndex, Environment environment, ThreadPool threadPool) {
        this.client = client;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
        this.threadPool = threadPool;
    }

    @Override
    public void execute(JobExecutionContext context) {
        // Offload execution to the generic thread pool to allow blocking operations
        this.threadPool.generic().execute(() -> {
            try {
                log.info("Executing Consumer Sync Job (ID: {})", context.getJobId());
                this.rulesConsumer();
                this.decodersConsumer();
            } catch (Exception e) {
                log.error("Error executing Consumer Sync Job (ID: {}): {}", context.getJobId(), e.getMessage(), e);
            }
        });
    }

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
        this.syncConsumerServices(context, consumer, mappings);
        log.info("Rules Consumer correctly synchronized.");
    }

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
        this.syncConsumerServices(context, consumer, mappings);
        log.info("Decoders Consumer correctly synchronized.");
    }

    private String getIndexName(String context, String consumer, String type) {
        return String.format(
            Locale.ROOT, ".%s-%s-%s",
            context,
            consumer,
            type
        );
    }

    private void syncConsumerServices(String context, String consumer, Map<String, String> mappings) {
        ConsumerService consumerService = new ConsumerServiceImpl(context, consumer, this.consumersIndex);
        LocalConsumer localConsumer = consumerService.getLocalConsumer(); // Blocking call
        RemoteConsumer remoteConsumer = consumerService.getRemoteConsumer(); // Blocking call

        log.info("Local consumer: {}", localConsumer);
        log.info("Remote consumer: {}", remoteConsumer);

        List<ContentIndex> indices = new ArrayList<>();

        for (Map.Entry<String, String> entry : mappings.entrySet()) {
            String indexName = this.getIndexName(context, consumer, entry.getKey());
            ContentIndex index = new ContentIndex(this.client, indexName, entry.getValue());
            indices.add(index);

            // Check if index exists to avoid creation exception
            boolean indexExists = this.client.admin().indices().prepareExists(indexName).get().isExists();

            if (!indexExists) {
                try {
                    CreateIndexResponse response = index.createIndex(); // Blocking call
                    if (response.isAcknowledged()) {
                        log.info("Index [{}] created successfully", response.index());
                    }
                } catch (Exception e) {
                    log.error("Failed to create index [{}]: {}", indexName, e.getMessage());
                }
            } else {
                log.info("Index [{}] already exists. Skipping creation.", indexName);
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
            snapshotService.initialize(remoteConsumer); // Blocking call
        } else if (remoteConsumer != null && localConsumer.getLocalOffset() != remoteConsumer.getOffset()) {
            // TODO: Implement offset based update process
        } else {
            log.info("Indices already initialized or remote consumer unavailable.");
        }
    }
}
