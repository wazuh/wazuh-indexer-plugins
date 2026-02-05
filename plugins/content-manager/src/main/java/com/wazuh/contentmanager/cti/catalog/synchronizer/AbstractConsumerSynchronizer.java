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
package com.wazuh.contentmanager.cti.catalog.synchronizer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.env.Environment;
import org.opensearch.transport.client.Client;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SnapshotServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.UpdateServiceImpl;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Base class for consumer synchronization logic. Provides common functionality for synchronizing
 * content between a remote CTI (Cyber Threat Intelligence) catalog and local OpenSearch indices.
 * Handles index creation with proper mappings and aliases, snapshot initialization for first-time
 * synchronization, and incremental updates based on offset tracking.
 *
 * <p>Subclasses must implement the abstract methods to define the specific context, consumer name,
 * mappings, aliases, and post-synchronization behavior.
 *
 * @see ConsumerService
 * @see SnapshotServiceImpl
 * @see UpdateServiceImpl
 */
public abstract class AbstractConsumerSynchronizer {
    private static final Logger log = LogManager.getLogger(AbstractConsumerSynchronizer.class);

    /** The OpenSearch client used for index operations. */
    protected final Client client;

    /** The consumers index for tracking synchronization state. */
    protected final ConsumersIndex consumersIndex;

    /** The OpenSearch environment configuration. */
    protected final Environment environment;

    public static final String POLICY = "policy";
    public static final String RULE = "rule";
    public static final String DECODER = "decoder";
    public static final String KVDB = "kvdb";
    public static final String INTEGRATION = "integration";

    /**
     * Constructs a new AbstractConsumerSynchronizer.
     *
     * @param client The OpenSearch client for index operations.
     * @param consumersIndex The index for tracking consumer synchronization state.
     * @param environment The OpenSearch environment configuration.
     */
    protected AbstractConsumerSynchronizer(
            Client client, ConsumersIndex consumersIndex, Environment environment) {
        this.client = client;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
    }

    /**
     * Returns the context name for this synchronizer. The context is used as part of the index naming
     * convention: .context-consumer-type
     *
     * @return The context name (e.g., "wazuh").
     */
    protected abstract String getContext();

    /**
     * Returns the consumer name for this synchronizer. The consumer identifies the type of content
     * being synchronized (e.g., "rules", "decoders").
     *
     * @return The consumer name.
     */
    protected abstract String getConsumer();

    /**
     * Returns the index mappings for this consumer. The map keys are type identifiers (used in index
     * naming), and values are the JSON mapping definitions for each index.
     *
     * @return A map of type to mapping definition.
     */
    protected abstract Map<String, String> getMappings();

    /**
     * Returns the index aliases for this consumer. The map keys are type identifiers (matching those
     * in getMappings()), and values are the alias names to create for each index.
     *
     * @return A map of type to alias name.
     */
    protected abstract Map<String, String> getAliases();

    /**
     * Called after synchronization completes. Subclasses should implement this to perform any
     * post-synchronization tasks such as triggering dependent operations or logging results.
     *
     * @param isUpdated True if any updates were applied during synchronization, false if already up
     *     to date.
     */
    protected abstract void onSyncComplete(boolean isUpdated);

    /**
     * Main synchronization entry point. Orchestrates the synchronization process by performing the
     * actual sync and calling onSyncComplete with the result.
     */
    public void synchronize() {
        boolean isUpdated = this.syncConsumerServices();
        this.onSyncComplete(isUpdated);
    }

    /**
     * Overrides index naming to utilize the alias name convention directly.
     *
     * @param type The type identifier for the index.
     * @return The unified index name.
     */
    public String getIndexName(String type) {
        return switch (type) {
            case RULE -> Constants.INDEX_RULES;
            case DECODER -> Constants.INDEX_DECODERS;
            case KVDB -> Constants.INDEX_KVDBS;
            case INTEGRATION -> Constants.INDEX_INTEGRATIONS;
            case POLICY -> Constants.INDEX_POLICIES;
            default -> throw new IllegalArgumentException("Unknown type: " + type);
        };
    }

    /**
     * Refreshes the specified indices to make recent changes searchable. Any errors during refresh
     * are logged as warnings but do not interrupt execution.
     *
     * @param indexNames The index names to refresh.
     */
    protected void refreshIndices(String... indexNames) {
        try {
            this.client.admin().indices().prepareRefresh(indexNames).get();
        } catch (Exception e) {
            log.warn("Error refreshing indices: {}", e.getMessage());
        }
    }

    /**
     * Performs the core synchronization logic for consumer services. Retrieves local and remote
     * consumer state, creates any missing indices with their mappings and aliases, initializes from
     * snapshot if this is a first-time sync (offset = 0), and applies incremental updates if the
     * remote offset is ahead.
     *
     * @return True if any updates were applied (snapshot or incremental), false if already up to
     *     date.
     */
    private boolean syncConsumerServices() {
        String context = this.getContext();
        String consumer = this.getConsumer();

        ConsumerService consumerService =
                new ConsumerServiceImpl(context, consumer, this.consumersIndex);
        LocalConsumer localConsumer = consumerService.getLocalConsumer();
        RemoteConsumer remoteConsumer = consumerService.getRemoteConsumer();

        Map<String, ContentIndex> indicesMap = new HashMap<>();

        for (Map.Entry<String, String> entry : this.getMappings().entrySet()) {
            String indexName = this.getIndexName(entry.getKey());
            String alias = this.getAliases().get(entry.getKey());
            ContentIndex index = new ContentIndex(this.client, indexName, entry.getValue(), alias);
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
            SnapshotServiceImpl snapshotService =
                    new SnapshotServiceImpl(
                            context, consumer, indicesMap, this.consumersIndex, this.environment);
            snapshotService.initialize(remoteConsumer);

            currentOffset = remoteConsumer.getSnapshotOffset();
            updated = true;
        }

        // Update
        if (remoteConsumer != null && currentOffset < remoteConsumer.getOffset()) {
            log.info(
                    "Performing update for consumer [{}] from offset [{}] to [{}]",
                    consumer,
                    currentOffset,
                    remoteConsumer.getOffset());

            UpdateServiceImpl updateService =
                    new UpdateServiceImpl(
                            context, consumer, new ApiClient(), this.consumersIndex, indicesMap);
            updateService.update(currentOffset, remoteConsumer.getOffset());
            updateService.close();
            updated = true;
        }
        return updated;
    }
}
