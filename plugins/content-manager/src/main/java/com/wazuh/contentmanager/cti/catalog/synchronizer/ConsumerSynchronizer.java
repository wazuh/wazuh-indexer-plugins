package com.wazuh.contentmanager.cti.catalog.synchronizer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.env.Environment;
import org.opensearch.transport.client.Client;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SnapshotServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.UpdateServiceImpl;

/**
 * Base class for consumer synchronization logic.
 * Provides common functionality for index creation, snapshot/update handling.
 */
public abstract class ConsumerSynchronizer {
    private static final Logger log = LogManager.getLogger(ConsumerSynchronizer.class);

    protected final Client client;
    protected final ConsumersIndex consumersIndex;
    protected final Environment environment;

    protected ConsumerSynchronizer(Client client, ConsumersIndex consumersIndex, Environment environment) {
        this.client = client;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
    }

    protected abstract String getContext();
    protected abstract String getConsumer();
    protected abstract Map<String, String> getMappings();
    protected abstract Map<String, String> getAliases();
    protected abstract void onSyncComplete(boolean isUpdated);

    /**
     * Main synchronization entry point.
     */
    public void synchronize() {
        boolean isUpdated = syncConsumerServices();
        onSyncComplete(isUpdated);
    }

    protected String getIndexName(String type) {
        return String.format(Locale.ROOT, ".%s-%s-%s", getContext(), getConsumer(), type);
    }

    protected void refreshIndices(String... types) {
        try {
            String[] indexNames = Arrays.stream(types)
                .map(this::getIndexName)
                .toArray(String[]::new);
            client.admin().indices().prepareRefresh(indexNames).get();
        } catch (Exception e) {
            log.warn("Error refreshing indices: {}", e.getMessage());
        }
    }

    private boolean syncConsumerServices() {
        String context = this.getContext();
        String consumer = this.getConsumer();

        ConsumerService consumerService = new ConsumerServiceImpl(context, consumer, this.consumersIndex);
        LocalConsumer localConsumer = consumerService.getLocalConsumer();
        RemoteConsumer remoteConsumer = consumerService.getRemoteConsumer();

        List<ContentIndex> indices = new ArrayList<>();
        Map<String, ContentIndex> indicesMap = new HashMap<>();

        for (Map.Entry<String, String> entry : getMappings().entrySet()) {
            String indexName = this.getIndexName(entry.getKey());
            String alias = getAliases().get(entry.getKey());
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
                } catch (InterruptedException | ExecutionException | TimeoutException e) {
                    log.error("Failed to create index [{}]: {}", indexName, e.getMessage());
                }
            }
        }

        boolean updated = false;
        long currentOffset = localConsumer != null ? localConsumer.getLocalOffset() : 0;

        // Snapshot Initialization
        if (remoteConsumer != null && remoteConsumer.getSnapshotLink() != null && currentOffset == 0) {
            log.info("Initializing snapshot from link: {}", remoteConsumer.getSnapshotLink());
            SnapshotServiceImpl snapshotService = new SnapshotServiceImpl(
                context,
                consumer,
                indices,
                this.consumersIndex,
                this.environment
            );
            snapshotService.initialize(remoteConsumer);

            currentOffset = remoteConsumer.getSnapshotOffset();
            updated = true;
        }

        // Update
        if (remoteConsumer != null && currentOffset < remoteConsumer.getOffset()) {
            log.info("Performing update for consumer [{}] from offset [{}] to [{}]", consumer, currentOffset, remoteConsumer.getOffset());

            UpdateServiceImpl updateService = new UpdateServiceImpl(
                context,
                consumer,
                new ApiClient(),
                this.consumersIndex,
                indicesMap
            );
            updateService.update(currentOffset, remoteConsumer.getOffset());
            updateService.close();
            updated = true;
        }
        return updated;
    }

    }
}