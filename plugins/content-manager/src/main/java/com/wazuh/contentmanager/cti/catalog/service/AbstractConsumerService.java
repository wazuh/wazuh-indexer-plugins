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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.GetResponse;
import org.opensearch.env.Environment;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.transport.client.Client;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Space;
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
public abstract class AbstractConsumerService {
    private static final Logger log = LogManager.getLogger(AbstractConsumerService.class);

    /** The OpenSearch client used for index operations. */
    protected final Client client;

    /** The consumers index for tracking synchronization state. */
    protected final ConsumersIndex consumersIndex;

    /** The OpenSearch environment configuration. */
    protected final Environment environment;

    /**
     * Constructs a new AbstractConsumerService.
     *
     * @param client The OpenSearch client for index operations.
     * @param consumersIndex The index for tracking consumer synchronization state.
     * @param environment The OpenSearch environment configuration.
     */
    protected AbstractConsumerService(
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
     * being synchronized (e.g., "Constants.KEY_RULEs", "Constants.KEY_DECODERs").
     *
     * @return The consumer name.
     */
    protected abstract String getConsumer();

    /** Returns the consumer type used as document id in `.wazuh-cti-consumers`. */
    protected abstract String getConsumerType();

    /** Returns the full CTI catalog consumer URL for this synchronizer. */
    protected abstract String getCatalogUri();

    /**
     * Indicates whether this consumer manages ruleset resources that require Security Analytics
     * cleanup on snapshot initialization.
     */
    protected boolean isRulesetConsumer() {
        return false;
    }

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
    public abstract void onSyncComplete(boolean isUpdated);

    /**
     * Returns the local snapshot filename for this consumer. The file is expected to reside in the
     * {@code snapshots} directory alongside the plugin installation.
     *
     * @return The snapshot zip filename (e.g., "ruleset.zip").
     */
    protected abstract String getSnapshotFilename();

    /** Factory hook for tests to override consumer service creation. */
    protected ConsumerService createConsumerService(
            String context, String consumer, String consumerType, String catalogUri) {
        return new ConsumerServiceImpl(
                context, consumer, consumerType, catalogUri, this.consumersIndex);
    }

    /** Factory hook for tests to override snapshot service creation. */
    protected SnapshotServiceImpl createSnapshotService(
            String context,
            String consumer,
            String consumerType,
            String catalogUri,
            Map<String, ContentIndex> indicesMap) {
        return new SnapshotServiceImpl(
                context,
                consumer,
                consumerType,
                catalogUri,
                indicesMap,
                this.consumersIndex,
                this.environment);
    }

    /** Factory hook for tests to override update service creation. */
    protected UpdateServiceImpl createUpdateService(
            String context,
            String consumer,
            String consumerType,
            String catalogUri,
            Map<String, ContentIndex> indicesMap) {
        return new UpdateServiceImpl(
                context,
                consumer,
                consumerType,
                catalogUri,
                new ApiClient(),
                this.consumersIndex,
                indicesMap);
    }

    /**
     * Main synchronization entry point. Orchestrates the synchronization process by performing the
     * actual sync and calling onSyncComplete with the result.
     *
     * <p>Marks the consumer as {@link LocalConsumer.Status#UPDATING} before sync begins so that
     * external components can detect the in-progress state. The status is restored to {@link
     * LocalConsumer.Status#IDLE} once synchronization completes, whether updates were applied.
     */
    public void synchronize() {
        this.setConsumerStatus(LocalConsumer.Status.UPDATING);
        boolean isUpdated = this.syncConsumerServices();
        log.info(
                "Synchronization completed for consumer [{}]. Updated: {}", this.getConsumer(), isUpdated);
        this.onSyncComplete(isUpdated);
        this.setConsumerStatus(LocalConsumer.Status.IDLE);
    }

    /**
     * Updates the consumer status in the {@code .wazuh-cti-consumers} index.
     *
     * @param status The new {@link LocalConsumer.Status} to persist.
     */
    private void setConsumerStatus(LocalConsumer.Status status) {
        String context = this.getContext();
        String consumer = this.getConsumer();
        String consumerType = this.getConsumerType();
        String catalogUri = this.getCatalogUri();
        try {
            GetResponse getResponse = this.consumersIndex.getConsumer(consumerType);
            boolean hasCurrent = getResponse != null && getResponse.isExists();
            LocalConsumer current =
                    hasCurrent
                            ? new ObjectMapper().readValue(getResponse.getSourceAsString(), LocalConsumer.class)
                            : new LocalConsumer(context, consumer, consumerType, catalogUri, true);
            String effectiveContext = this.firstNonBlank(current.getContext(), context);
            String effectiveName = this.firstNonBlank(current.getName(), consumer);
            String effectiveType = this.firstNonBlank(current.getType(), consumerType);
            String effectiveResource = this.firstNonBlank(current.getResource(), catalogUri);
            boolean effectiveIsPublic = hasCurrent ? current.isPublic() : true;
            LocalConsumer updated =
                    new LocalConsumer(
                            effectiveContext,
                            effectiveName,
                            effectiveType,
                            effectiveResource,
                            effectiveIsPublic,
                            status,
                            current.getLocalOffset(),
                            current.getRemoteOffset());
            this.consumersIndex.setConsumer(updated);
            log.debug("Consumer [{}] status set to [{}]", consumer, status);
        } catch (Exception e) {
            log.warn("Failed to set consumer [{}] status to [{}]: {}", consumer, status, e.getMessage());
        }
    }

    /**
     * Overrides index naming to utilize the alias name convention directly.
     *
     * @param type The type identifier for the index.
     * @return The unified index name.
     */
    public String getIndexName(String type) {
        // TODO Normalize the Resource types at resource creation to avoid this mapping and simplify
        // index management
        // e.g. always use the `type` in plural (decoders, rules, etc.) and remove the need for this
        // mapping
        return switch (type) {
            case Constants.KEY_RULE -> Constants.INDEX_RULES;
            case Constants.KEY_DECODER -> Constants.INDEX_DECODERS;
            case Constants.KEY_KVDB -> Constants.INDEX_KVDBS;
            case Constants.KEY_INTEGRATION -> Constants.INDEX_INTEGRATIONS;
            case Constants.KEY_POLICY -> Constants.INDEX_POLICIES;
            case Constants.KEY_FILTERS -> Constants.INDEX_FILTERS;
            case Constants.KEY_IOCS -> Constants.INDEX_IOCS;
            case Constants.KEY_CVES -> Constants.INDEX_CVES;
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
        String consumerType = this.getConsumerType();

        String catalogUri = this.getCatalogUri();

        ConsumerService consumerService =
                this.createConsumerService(context, consumer, consumerType, catalogUri);
        LocalConsumer localConsumer = consumerService.getLocalConsumer();
        RemoteConsumer remoteConsumer =
                (catalogUri != null && !catalogUri.isBlank()) ? consumerService.getRemoteConsumer() : null;

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

        // Offset mismatch resilience
        if (localConsumer != null && remoteConsumer != null) {
            if (currentOffset > remoteConsumer.getOffset()) {
                log.warn(
                        "Local offset [{}] exceeds remote offset [{}] for consumer [{}]. Resetting.",
                        currentOffset,
                        remoteConsumer.getOffset(),
                        consumer);
                currentOffset = 0;
            }
        }

        if (currentOffset == 0) {
            Path snapshotsDir =
                    this.environment
                            .pluginsDir()
                            .resolve(Constants.PLUGIN_DIR_NAME)
                            .resolve(Constants.CTI_SNAPSHOTS_DIR);
            Path localSnapshot = snapshotsDir.resolve(this.getSnapshotFilename());

            // Load the external manifest entry for this snapshot (keyed by snapshot filename).
            JsonNode manifestEntry = this.loadExternalManifestEntry(snapshotsDir);

            boolean snapshotExists;
            try {
                snapshotExists = AccessController.doPrivilegedChecked(() -> Files.exists(localSnapshot));
            } catch (Exception e) {
                log.warn("Failed to check local snapshot at [{}]: {}", localSnapshot, e.getMessage());
                snapshotExists = false;
            }

            boolean hasCustomCatalog = catalogUri != null && !catalogUri.isBlank();

            // For custom URLs, prefer remote initialization and fallback to local snapshot on failure.
            if (hasCustomCatalog && remoteConsumer != null && remoteConsumer.getSnapshotLink() != null) {
                // Ruleset snapshots also affect Security Analytics/Space resources; other catalogs only
                // clear indices.
                if (this.isRulesetConsumer()) {
                    try {
                        SecurityAnalyticsService securityAnalyticsService =
                                new SecurityAnalyticsServiceImpl(this.client);
                        securityAnalyticsService.deleteSpaceResources(Space.STANDARD);
                        SpaceService spaceService = new SpaceService(this.client);
                        spaceService.deleteSpaceResources(Space.STANDARD);
                    } catch (Exception e) {
                        log.error(
                                "Failed to clear existing resources for consumer [{}] during snapshot initialization: {}",
                                consumer,
                                e.getMessage());
                    }
                } else {
                    indicesMap.values().forEach(ContentIndex::clear);
                }

                log.info("Initializing snapshot from custom consumer URL: {}", catalogUri);
                SnapshotServiceImpl snapshotService =
                        this.createSnapshotService(context, consumer, consumerType, catalogUri, indicesMap);

                boolean remoteSuccess = snapshotService.initialize(remoteConsumer);
                if (remoteSuccess) {
                    currentOffset = remoteConsumer.getSnapshotOffset();
                    updated = true;
                    if (snapshotExists) {
                        this.deleteLocalSnapshot(localSnapshot, consumer);
                    }
                } else if (snapshotExists) {
                    log.warn(
                            "Remote snapshot initialization failed for consumer [{}]. Falling back to local snapshot [{}].",
                            consumer,
                            localSnapshot);
                    boolean localSuccess = snapshotService.initialize(localSnapshot, manifestEntry);
                    if (localSuccess) {
                        currentOffset = this.resolveLocalOffset(snapshotService, manifestEntry);
                        updated = true;
                    } else {
                        log.warn("Local snapshot fallback failed for consumer [{}].", consumer);
                    }
                } else {
                    log.warn(
                            "Remote snapshot initialization failed for consumer [{}] and no local snapshot was found at [{}].",
                            consumer,
                            localSnapshot);
                }
            } else if (snapshotExists) {
                // No custom URL configured: initialize from local snapshot only.
                log.info("Initializing consumer [{}] from local snapshot [{}]", consumer, localSnapshot);
                SnapshotServiceImpl snapshotService =
                        this.createSnapshotService(context, consumer, consumerType, catalogUri, indicesMap);

                boolean localSuccess = snapshotService.initialize(localSnapshot, manifestEntry);
                if (localSuccess) {
                    currentOffset = this.resolveLocalOffset(snapshotService, manifestEntry);
                    updated = true;
                } else {
                    log.warn("Local snapshot initialization failed for consumer [{}].", consumer);
                }
            } else if (hasCustomCatalog) {
                log.warn(
                        "No local snapshot found at [{}] and custom consumer initialization could not be completed for [{}].",
                        localSnapshot,
                        consumer);
            } else {
                log.info(
                        "No local snapshot at [{}] for consumer [{}] and no custom consumer URL is configured.",
                        localSnapshot,
                        consumer);
            }
        }

        // Incremental Update
        if (remoteConsumer != null && currentOffset < remoteConsumer.getOffset()) {
            log.info(
                    "Performing update for consumer [{}] from offset [{}] to [{}]",
                    consumer,
                    currentOffset,
                    remoteConsumer.getOffset());

            UpdateServiceImpl updateService =
                    this.createUpdateService(context, consumer, consumerType, catalogUri, indicesMap);
            updateService.update(currentOffset, remoteConsumer.getOffset());
            updateService.close();
            updated = true;
        }
        return updated;
    }

    private void deleteLocalSnapshot(Path localSnapshot, String consumer) {
        try {
            boolean deleted =
                    AccessController.doPrivilegedChecked(() -> Files.deleteIfExists(localSnapshot));
            if (deleted) {
                log.info(
                        "Removed local snapshot [{}] after successful custom initialization for consumer [{}].",
                        localSnapshot,
                        consumer);
            }
        } catch (Exception e) {
            log.warn("Failed to delete local snapshot [{}]: {}", localSnapshot, e.getMessage());
        }
    }

    /**
     * Loads the external {@code manifest.json} from the snapshots directory and returns the metadata
     * entry for this consumer's snapshot file. The manifest is a JSON object keyed by snapshot
     * filename (e.g., {@code "ruleset.zip"}).
     *
     * @param snapshotsDir The directory that contains the snapshot zip files and the manifest.
     * @return The {@link JsonNode} for this consumer's snapshot, or {@code null} if the manifest does
     *     not exist or the entry is missing.
     */
    private JsonNode loadExternalManifestEntry(Path snapshotsDir) {
        Path manifestPath = snapshotsDir.resolve(Constants.MANIFEST_FILENAME);
        try {
            boolean exists = AccessController.doPrivilegedChecked(() -> Files.exists(manifestPath));
            if (!exists) {
                log.warn(
                        "External manifest not found at [{}]. Using service defaults for consumer [{}].",
                        manifestPath,
                        this.getConsumer());
                return null;
            }

            byte[] bytes = AccessController.doPrivilegedChecked(() -> Files.readAllBytes(manifestPath));
            JsonNode root = new ObjectMapper().readTree(bytes);
            String snapshotFilename = this.getSnapshotFilename();
            JsonNode entry = root.get(snapshotFilename);
            if (entry == null || entry.isNull()) {
                log.warn(
                        "External manifest [{}] has no entry for snapshot [{}]. Using service defaults for consumer [{}].",
                        manifestPath,
                        snapshotFilename,
                        this.getConsumer());
                return null;
            }
            log.info(
                    "Loaded manifest entry for snapshot [{}] from [{}]. Entry content: {}",
                    snapshotFilename,
                    manifestPath,
                    entry.toString());
            return entry;
        } catch (Exception e) {
            log.warn(
                    "Failed to load external manifest from [{}]: {}. Using service defaults for consumer [{}].",
                    manifestPath,
                    e.getMessage(),
                    this.getConsumer());
            return null;
        }
    }

    /**
     * Resolves the local offset to use after a local snapshot has been initialised. Prefers the
     * {@code remote_offset} value from the external manifest entry (the authoritative snapshot
     * offset), and falls back to the maximum offset seen while processing the snapshot files.
     *
     * @param snapshotService The snapshot service that just finished processing.
     * @param manifestEntry The external manifest entry for this consumer, or {@code null}.
     * @return The resolved offset.
     */
    private long resolveLocalOffset(SnapshotServiceImpl snapshotService, JsonNode manifestEntry) {
        if (manifestEntry != null
                && manifestEntry.has("remote_offset")
                && !manifestEntry.get("remote_offset").isNull()) {
            long remoteOffset = manifestEntry.get("remote_offset").asLong();
            log.debug(
                    "Resolved offset from manifest remote_offset: {} (snapshotMaxOffsetSeen={})",
                    remoteOffset,
                    snapshotService.getMaxOffsetSeen());
            return remoteOffset;
        }
        long maxOffsetSeen = snapshotService.getMaxOffsetSeen();
        log.debug("Resolved offset from snapshot max offset seen: {}", maxOffsetSeen);
        return maxOffsetSeen;
    }

    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
