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
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.env.Environment;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.transport.client.Client;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.action.PromoteSnapshotAction;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.client.RegularUrlResolver;
import com.wazuh.contentmanager.cti.catalog.client.ResourceUrlResolver;
import com.wazuh.contentmanager.cti.catalog.client.SignedUrlResolver;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.console.service.CtiConsoleUnavailableException;
import com.wazuh.contentmanager.cti.console.service.TokenExchangeServiceImpl;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.transport.TransportPromoteSnapshotAction;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.UrlUtils;

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
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The OpenSearch client used for index operations. */
    protected final Client client;

    /** The consumers index for tracking synchronization state. */
    protected final ConsumersIndex consumersIndex;

    /** The OpenSearch environment configuration. */
    protected final Environment environment;

    /** Optional override for the consumer service, used by tests to inject mocks. */
    private ConsumerService consumerServiceOverride;

    /** Optional override for the snapshot service, used by tests to inject mocks. */
    private SnapshotServiceImpl snapshotServiceOverride;

    /**
     * Set to {@code true} after a successful shadow swap so subclasses can clean up stale resources.
     */
    protected boolean shadowSwapPerformed;

    /**
     * Set by {@link #requestImmediateRetry()} when a pass completed but did not leave the consumer in
     * the state it was meant to reach, so {@link #synchronize()} can ask the caller for one immediate
     * retry
     */
    private volatile boolean immediateRetryRequested;

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

    /** Returns the consumer type used as document id in `.wazuh-cti-consumers`. */
    protected abstract String getConsumerType();

    /** Returns the full CTI catalog consumer URL for this synchronizer. */
    protected abstract String getCustomCatalogUri();

    /**
     * Indicates whether this consumer manages ruleset resources that require Security Analytics
     * cleanup on snapshot initialization.
     */
    protected boolean isRulesetConsumer() {
        return false;
    }

    /**
     * Indicates whether this consumer manages indices with user-edited content (draft, test, custom
     * spaces) that must be preserved across blue/green swaps. Subclasses that manage ruleset content
     * should override this to return {@code true}.
     */
    protected boolean hasUserContent() {
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

    /**
     * Resolves the plugin's snapshots directory on this node. Package-private so tests can point it
     * at a directory of their own.
     *
     * @return the directory, or {@code null} when there is none, as in test environments.
     */
    Path resolveSnapshotsDir() {
        // Snapshots dir do not exist on development environments.
        if (ContentManagerPlugin.isTestEnvironment()) {
            return null;
        }
        Path pluginsDir = this.environment.pluginsDir();
        return pluginsDir == null
                ? null
                : pluginsDir.resolve(Constants.PLUGIN_DIR_NAME).resolve(Constants.CTI_SNAPSHOTS_DIR);
    }

    /**
     * Reports whether a snapshot file of this consumer waits to be loaded in the snapshots directory
     * of this node: the packaged one, or one an operator placed there for an offline update. A loaded
     * snapshot is kept as the stable one under another name, so it does not count.
     *
     * @return {@code true} if the file exists.
     */
    public boolean hasLocalSnapshot() {
        try {
            Path snapshotsDir = this.resolveSnapshotsDir();
            return snapshotsDir != null
                    && snapshotFileExists(snapshotsDir.resolve(this.getSnapshotFilename()));
        } catch (Exception e) {
            log.debug(
                    Constants.D_LOG_SNAPSHOTS_DIR_RESOLVE_FAILED, this.getConsumerType(), e.getMessage());
            return false;
        }
    }

    /**
     * Checks whether a snapshot file exists.
     *
     * @param snapshot The file, or {@code null}.
     * @return {@code true} if it exists; {@code false} if it does not or cannot be checked.
     */
    private static boolean snapshotFileExists(Path snapshot) {
        if (snapshot == null) {
            return false;
        }
        try {
            return AccessController.doPrivilegedChecked(() -> Files.exists(snapshot));
        } catch (Exception e) {
            log.warn(Constants.W_LOG_LOCAL_SNAPSHOT_CHECK_FAILED, snapshot, e.getMessage());
            return false;
        }
    }

    /**
     * Hook called by {@link ShadowSwapService} just before the atomic alias swap. Subclasses can
     * override this to capture pre-swap state (e.g., collect resource IDs that may become stale after
     * the swap). The default implementation is a no-op.
     */
    protected void onBeforeAliasSwap() {}

    /**
     * Returns the post-synchronization phases that a change to this consumer's content leaves owed
     * until {@link #onSyncComplete(boolean)} has run them. They are recorded as pending before the
     * content changes: the local offset moves with the content, so a pass cut before {@link
     * #onSyncComplete(boolean)}, by a node shutdown or an exception, would otherwise leave an
     * up-to-date offset with nothing pending, and no later pass would run them. The default
     * implementation owes nothing.
     *
     * @return the owed phase names.
     */
    protected List<String> phasesOwedByContentChange() {
        return Collections.emptyList();
    }

    /** Injects a {@link ConsumerService} instance, used by tests to provide a mock. */
    public void setConsumerService(ConsumerService consumerService) {
        this.consumerServiceOverride = consumerService;
    }

    /** Injects a {@link SnapshotServiceImpl} instance, used by tests to provide a mock. */
    public void setSnapshotService(SnapshotServiceImpl snapshotService) {
        this.snapshotServiceOverride = snapshotService;
    }

    /**
     * Requests that the caller retry this consumer immediately instead of waiting for the next
     * scheduled run
     */
    protected void requestImmediateRetry() {
        this.immediateRetryRequested = true;
    }

    /**
     * Synchronizes this consumer alone, in a pass of its own: looks the plan up, moves the consumer
     * to a new data source if it has one, through {@link ShadowSwapService}, and then runs {@link
     * #synchronize(SyncPass)}.
     *
     * @return see {@link #synchronize(SyncPass)}.
     */
    boolean synchronize() {
        SyncPass pass = SyncPass.resolve();
        new ShadowSwapService(this.client, this.consumersIndex).swapChangedSources(List.of(this), pass);
        return this.synchronize(pass);
    }

    /**
     * Main synchronization entry point. Orchestrates the synchronization process by performing the
     * actual sync and calling onSyncComplete with the result.
     *
     * <p>A change of data source is not applied here: the pass's {@link ShadowSwapService} moves all
     * changing consumers together before this runs, and its outcome for this consumer is in the pass.
     * A consumer it moved catches up from the loaded snapshot to the remote head and runs its
     * post-synchronization work as an update. A consumer whose change could not be applied keeps its
     * current content, and one the swap left on hold is not touched at all.
     *
     * <p>Marks the consumer as {@link LocalConsumer.Status#RUNNING} before any content is applied so
     * that external components can detect the in-progress state. When the remote head of the data
     * source the document describes is known, the same write records it as the remote offset while
     * keeping the local one, so from the first {@code running} read until the pass completes, the
     * document shows the gap still to be applied. The status moves to {@link
     * LocalConsumer.Status#READY} once synchronization actually completes, or to {@link
     * LocalConsumer.Status#FAILED} if an unexpected exception interrupts the sync; the exception is
     * then rethrown so the caller ({@code CatalogSyncJob}) can log it and continue with the remaining
     * synchronizers. If the pass was aborted before touching any content because the Setup plugin has
     * not yet provisioned this consumer's target indices, the status is left at {@code RUNNING}
     * rather than {@code READY} — nothing was synced, so nothing completed.
     *
     * @param pass The pass this synchronization belongs to.
     * @return {@code true} when the caller should retry this consumer immediately instead of waiting
     *     for the next scheduled run: a catalog URL was configured but the remote feed could not be
     *     reached (the pass still completes by falling back to the local snapshot, and the status is
     *     still moved to {@link LocalConsumer.Status#READY}), the target indices were not yet
     *     provisioned (nothing was synced, status stays {@code RUNNING}), a change of data source is
     *     still to be applied, or {@link #onSyncComplete(boolean)} called {@link
     *     #requestImmediateRetry()} because the pass left work undone. {@code false} when the pass
     *     reached the state it was meant to reach.
     */
    public boolean synchronize(SyncPass pass) {
        this.immediateRetryRequested = false;
        SyncPass.SwapOutcome swap = pass.swapOutcome(this.getConsumerType());
        if (swap == SyncPass.SwapOutcome.HELD) {
            // The document may name the data source a swap is moving this consumer to rather than
            // its live content: only a swap may change either of them.
            log.warn(Constants.W_LOG_SWAP_HELD, this.getConsumerType());
            return true;
        }
        try {
            SyncResult result = this.syncConsumerServices(pass);
            log.debug(Constants.D_LOG_SYNC_COMPLETED, this.getConsumerType(), result.updated());
            if (result.indicesMissing()) {
                // Nothing was synced: do not report a completion that did not happen. Status stays
                // RUNNING (set by syncConsumerServices); the caller retries immediately rather than
                // waiting for the next scheduled sync, since the Setup plugin usually finishes
                // provisioning within seconds.
                return true;
            }
            this.onSyncComplete(result.updated() || swap == SyncPass.SwapOutcome.SWAPPED);
            this.setConsumerStatus(LocalConsumer.Status.READY);
            return result.feedUnreachable()
                    || result.sourceChangePending()
                    || this.immediateRetryRequested;
        } catch (Exception e) {
            this.setConsumerStatus(LocalConsumer.Status.FAILED);
            throw new RuntimeException(
                    "Synchronization failed for consumer [" + this.getConsumerType() + "]", e);
        }
    }

    /**
     * Outcome of {@link #syncConsumerServices(SyncPass)}.
     *
     * @param updated {@code true} if any content update (snapshot or incremental) was applied.
     * @param feedUnreachable {@code true} if a catalog URL was configured but the remote consumer
     *     could not be fetched, so the pass relied on the local-snapshot fallback (or applied no
     *     remote changes at all).
     * @param indicesMissing {@code true} if the pass was aborted before touching any content because
     *     {@link #missingTargetIndices()} found the Setup plugin has not yet provisioned this
     *     consumer's target indices. Nothing was synced, so the caller must not report completion.
     * @param sourceChangePending {@code true} if the data source of the consumer changes but the swap
     *     that applies the change did not run, so the current content was kept as it is.
     */
    private record SyncResult(
            boolean updated,
            boolean feedUnreachable,
            boolean indicesMissing,
            boolean sourceChangePending) {}

    /**
     * Where the content of a consumer comes from in a pass.
     *
     * @param snapshotsDir The plugin's snapshots directory, or {@code null} when there is none.
     * @param localSnapshot The packaged snapshot of the consumer, or {@code null}.
     * @param manifestEntry The consumer's entry in the snapshots manifest, or {@code null}.
     * @param catalogUri The catalog URL the pass synchronizes from, or {@code null} when there is
     *     none.
     * @param swapTarget The data source the consumer moves to, or {@code null} when it stays on its
     *     current one.
     */
    record ContentSource(
            Path snapshotsDir,
            Path localSnapshot,
            JsonNode manifestEntry,
            String catalogUri,
            String swapTarget) {

        /** Returns whether the consumer moves to another data source. */
        boolean changes() {
            return this.swapTarget != null;
        }
    }

    /**
     * Updates the consumer status in the {@code .wazuh-cti-consumers} index. This is a partial
     * update: it preserves all identity fields and offsets, mutating only {@code status}. When the
     * consumer document does not yet exist (i.e., t0 has not run), the call is a no-op since identity
     * fields would not be derivable.
     *
     * @param status The new {@link LocalConsumer.Status} to persist.
     */
    private void setConsumerStatus(LocalConsumer.Status status) {
        this.setConsumerStatus(status, null);
    }

    /**
     * Updates the consumer status in the {@code .wazuh-cti-consumers} index and, in the same write,
     * the remote offset when one is given. This is a partial update: it preserves all identity fields
     * and the local offset, so a remote offset ahead of it shows the gap still to be applied. When
     * the consumer document does not yet exist (i.e., t0 has not run), the call is a no-op since
     * identity fields would not be derivable.
     *
     * @param status The new {@link LocalConsumer.Status} to persist.
     * @param remoteOffset The remote offset to persist with it, or {@code null} to keep the current
     *     one.
     */
    private void setConsumerStatus(LocalConsumer.Status status, Long remoteOffset) {
        String consumerType = this.getConsumerType();
        try {
            GetResponse response = this.consumersIndex.getConsumer(consumerType);
            if (response == null || !response.isExists()) {
                log.debug(Constants.D_LOG_CONSUMER_DOC_ABSENT, consumerType, status);
                return;
            }
            LocalConsumer current = MAPPER.readValue(response.getSourceAsString(), LocalConsumer.class);
            LocalConsumer updated =
                    new LocalConsumer(
                            current.getContext(),
                            current.getName(),
                            current.getType(),
                            current.getResource(),
                            current.isPublic(),
                            status,
                            current.getLocalOffset(),
                            remoteOffset != null ? remoteOffset : current.getRemoteOffset(),
                            current.getPendingSyncPhases());
            this.consumersIndex.setConsumer(updated);
            log.debug(Constants.D_LOG_CONSUMER_STATUS_SET, consumerType, status);
            if (remoteOffset != null) {
                log.debug(
                        Constants.D_LOG_CONSUMER_REMOTE_OFFSET_SET,
                        consumerType,
                        current.getLocalOffset(),
                        remoteOffset);
            }
        } catch (Exception e) {
            log.warn(Constants.W_LOG_CONSUMER_STATUS_FAILED, consumerType, status, e.getMessage());
        }
    }

    /**
     * Reads this consumer's document from {@code .wazuh-cti-consumers}.
     *
     * @return the document, or {@code null} if it does not exist.
     * @throws Exception if the document cannot be read.
     */
    LocalConsumer readConsumerDocument() throws Exception {
        GetResponse response = this.consumersIndex.getConsumer(this.getConsumerType());
        if (response == null || !response.isExists()) {
            return null;
        }
        return MAPPER.readValue(response.getSourceAsString(), LocalConsumer.class);
    }

    /**
     * Reads the names of SAP sync sub-phases still owed a retry from the {@code .wazuh-cti-consumers}
     * document, so a caller can re-attempt them on a pass that otherwise has nothing new to sync.
     * Read failures and an absent document are treated as "nothing pending" rather than propagated,
     * so a transient read error never permanently wedges a retry.
     *
     * @return The pending phase names, or an empty list if none are pending or the document is
     *     absent/unreadable.
     */
    protected List<String> readPendingSyncPhases() {
        String consumerType = this.getConsumerType();
        try {
            GetResponse response = this.consumersIndex.getConsumer(consumerType);
            if (response == null || !response.isExists()) {
                return Collections.emptyList();
            }
            LocalConsumer current = MAPPER.readValue(response.getSourceAsString(), LocalConsumer.class);
            List<String> phases = current.getPendingSyncPhases();
            return phases != null ? phases : Collections.emptyList();
        } catch (Exception e) {
            log.debug(Constants.D_LOG_CONSUMER_PENDING_PHASES_READ_FAILED, consumerType, e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Persists the names of SAP sync sub-phases still owed a retry to the {@code
     * .wazuh-cti-consumers} document. This is a partial update: it preserves all identity fields,
     * status and offsets, mutating only {@code pending_sync_phases}. When the consumer document does
     * not yet exist, the call is a no-op since identity fields would not be derivable.
     *
     * @param phases The pending phase names to persist; an empty list clears all pending phases.
     */
    protected void setPendingSyncPhases(List<String> phases) {
        String consumerType = this.getConsumerType();
        try {
            GetResponse response = this.consumersIndex.getConsumer(consumerType);
            if (response == null || !response.isExists()) {
                log.debug(Constants.D_LOG_CONSUMER_PENDING_PHASES_DOC_ABSENT, consumerType, phases);
                return;
            }
            LocalConsumer current = MAPPER.readValue(response.getSourceAsString(), LocalConsumer.class);
            LocalConsumer updated =
                    new LocalConsumer(
                            current.getContext(),
                            current.getName(),
                            current.getType(),
                            current.getResource(),
                            current.isPublic(),
                            current.getStatus(),
                            current.getLocalOffset(),
                            current.getRemoteOffset(),
                            phases);
            this.consumersIndex.setConsumer(updated);
        } catch (Exception e) {
            log.warn(Constants.W_LOG_CONSUMER_PENDING_PHASES_FAILED, consumerType, e.getMessage());
        }
    }

    /**
     * Records the phases {@link #phasesOwedByContentChange()} names as pending, keeping those already
     * pending, before this pass changes the consumer's content. Unlike {@link
     * #setPendingSyncPhases(List)}, a failed write stops the pass: changing the content without the
     * record is what lets a pass cut before {@link #onSyncComplete(boolean)} drop those phases for
     * good. When the consumer document does not exist there is no local offset that could get ahead
     * of the phases, so nothing is recorded.
     *
     * @throws IllegalStateException if the phases cannot be recorded.
     */
    void recordPhasesOwedByContentChange() {
        List<String> owed = this.phasesOwedByContentChange();
        if (owed.isEmpty()) {
            return;
        }
        String consumerType = this.getConsumerType();
        try {
            LocalConsumer current = this.readConsumerDocument();
            if (current == null) {
                return;
            }
            List<String> pending = mergePhases(current.getPendingSyncPhases(), owed);
            if (pending.equals(current.getPendingSyncPhases())) {
                return;
            }
            this.consumersIndex.setConsumer(
                    new LocalConsumer(
                            current.getContext(),
                            current.getName(),
                            current.getType(),
                            current.getResource(),
                            current.isPublic(),
                            current.getStatus(),
                            current.getLocalOffset(),
                            current.getRemoteOffset(),
                            pending));
            log.debug(Constants.D_LOG_CONSUMER_PHASES_OWED_RECORDED, consumerType, pending);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Could not record the sync phases owed by consumer ["
                            + consumerType
                            + "] before changing its content",
                    e);
        }
    }

    /**
     * Returns the pending phases with the owed ones appended, without duplicates.
     *
     * @param pending The phases already pending, or {@code null}.
     * @param owed The phases to add.
     * @return the merged phases, the pending ones first.
     */
    static List<String> mergePhases(List<String> pending, List<String> owed) {
        List<String> merged = new ArrayList<>(pending != null ? pending : Collections.emptyList());
        for (String phase : owed) {
            if (!merged.contains(phase)) {
                merged.add(phase);
            }
        }
        return merged;
    }

    /**
     * Returns the {@code resource} value from the existing consumer document, or {@code null} when
     * the document is absent / unreadable / has no resource. Used as a fallback catalog URL when the
     * configured setting is empty.
     */
    private String readExistingConsumerResource(String consumerType) {
        try {
            GetResponse response = this.consumersIndex.getConsumer(consumerType);
            if (response == null || !response.isExists()) {
                return null;
            }
            LocalConsumer current = MAPPER.readValue(response.getSourceAsString(), LocalConsumer.class);
            String resource = current.getResource();
            return (resource != null && !resource.isBlank()) ? resource : null;
        } catch (Exception e) {
            log.debug(Constants.D_LOG_CONSUMER_RESOURCE_READ_FAILED, consumerType, e.getMessage());
            return null;
        }
    }

    /**
     * Persists the initial (t0) consumer state to the {@code .wazuh-cti-consumers} index before
     * snapshot loading begins. Identity fields come from the remote response when a custom URL is
     * configured, otherwise from the manifest entry. {@code local_offset} is set to 0 (no data loaded
     * yet); {@code remote_offset} is the latest offset known upstream (so the post-load incremental
     * update can close the gap).
     *
     * <p>If neither the remote consumer nor the manifest entry is available, the write is skipped;
     * the existing fatal log branches in {@code syncConsumerServices} apply.
     */
    private void writeInitialConsumer(
            RemoteConsumer remoteConsumer,
            JsonNode manifestEntry,
            String catalogUri,
            String consumerType) {
        try {
            LocalConsumer t0;
            if (remoteConsumer != null) {
                t0 =
                        new LocalConsumer(
                                remoteConsumer.getContext(),
                                remoteConsumer.getName(),
                                consumerType,
                                catalogUri,
                                remoteConsumer.isPublic(),
                                LocalConsumer.Status.RUNNING,
                                0,
                                remoteConsumer.getOffset());
            } else if (manifestEntry != null) {
                String mName = this.readManifestString(manifestEntry, Constants.KEY_NAME, "");
                String mContext = this.readManifestString(manifestEntry, Constants.KEY_CONTEXT, "");
                String mType = this.readManifestString(manifestEntry, Constants.KEY_TYPE, consumerType);
                String mResource = this.readManifestString(manifestEntry, Constants.KEY_RESOURCE, "");
                boolean mIsPublic = this.readManifestBoolean(manifestEntry, Constants.KEY_IS_PUBLIC, true);
                long mRemoteOffset = this.readManifestLong(manifestEntry, Constants.KEY_REMOTE_OFFSET, 0);
                t0 =
                        new LocalConsumer(
                                mContext,
                                mName,
                                mType,
                                mResource,
                                mIsPublic,
                                LocalConsumer.Status.RUNNING,
                                0,
                                mRemoteOffset);
            } else {
                return;
            }
            this.consumersIndex.setConsumer(t0);
            log.debug(Constants.D_LOG_CONSUMER_T0_WRITTEN, consumerType, t0.getRemoteOffset());
        } catch (Exception e) {
            log.warn(Constants.W_LOG_CONSUMER_T0_FAILED, consumerType, e.getMessage());
        }
    }

    private String readManifestString(JsonNode node, String field, String defaultValue) {
        if (node != null && node.has(field) && !node.get(field).isNull()) {
            String value = node.get(field).asText(defaultValue);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return defaultValue;
    }

    private long readManifestLong(JsonNode node, String field, long defaultValue) {
        if (node != null && node.has(field) && !node.get(field).isNull()) {
            return node.get(field).asLong(defaultValue);
        }
        return defaultValue;
    }

    private boolean readManifestBoolean(JsonNode node, String field, boolean defaultValue) {
        if (node != null && node.has(field) && !node.get(field).isNull()) {
            return node.get(field).asBoolean(defaultValue);
        }
        return defaultValue;
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
            case Constants.KEY_FILTER -> Constants.INDEX_FILTERS;
            case Constants.KEY_IOCS -> Constants.INDEX_IOCS;
            case Constants.KEY_CVES -> Constants.INDEX_CVES;
            default -> throw new IllegalArgumentException("Unknown type: " + type);
        };
    }

    /**
     * Returns the target indices of this consumer that do not exist.
     *
     * <p>The Setup plugin creates each one as {@code <name>-a} with the public alias {@code <name>}
     * pointing at it, and marks itself ready only once they are all in place, so on a correctly
     * configured cluster this is always empty. A name is reported missing when neither an index nor
     * an alias answers to it.
     *
     * @return the absent index names, empty when they all exist.
     */
    public List<String> missingTargetIndices() {
        List<String> missing = new ArrayList<>();
        for (String type : this.getMappings().keySet()) {
            String indexName = this.getIndexName(type);
            if (!this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                missing.add(indexName);
            }
        }
        return missing;
    }

    /**
     * Returns the public aliases of this consumer's content indices.
     *
     * @return the alias names.
     */
    List<String> aliases() {
        return this.getMappings().keySet().stream().map(this::getIndexName).toList();
    }

    /**
     * Returns whether an index holds no documents. A read failure is reported as "not empty" so a
     * transient error never triggers a full content re-download.
     *
     * @param indexName The index (or alias) to count documents on.
     * @return true when the index is reachable and holds no documents, false otherwise.
     */
    private boolean isIndexEmpty(String indexName) {
        try {
            SearchResponse response =
                    this.client
                            .prepareSearch(indexName)
                            .setSize(0)
                            .setTrackTotalHits(true)
                            .get(TimeValue.timeValueSeconds(PluginSettings.getInstance().getClientTimeout()));
            return response.getHits().getTotalHits().value() == 0;
        } catch (Exception e) {
            log.debug(Constants.D_LOG_INDEX_COUNT_FAILED, indexName, e.getMessage());
            return false;
        }
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
            log.warn(Constants.W_LOG_REFRESH_INDICES_FAILED, e.getMessage());
        }
    }

    /**
     * Resolves where this consumer's content comes from in a pass, and whether the pass moves it to
     * another data source.
     *
     * @param pass The pass, which holds the plan.
     * @return the content source.
     */
    ContentSource resolveContentSource(SyncPass pass) {
        String consumerType = this.getConsumerType();

        // Resolve the snapshots directory and load the external manifest entry once up front. The
        // manifest doubles as a source of identity and as a fallback catalog URL when no setting /
        // no existing doc is available. Resolution is defensive: a missing pluginsDir (e.g. in
        // tests with a minimally-stubbed Environment) is treated as "no snapshots / no manifest".
        Path snapshotsDir = null;
        Path localSnapshot = null;
        JsonNode manifestEntry = null;
        try {
            snapshotsDir = this.resolveSnapshotsDir();
            if (snapshotsDir != null) {
                localSnapshot = snapshotsDir.resolve(this.getSnapshotFilename());
                manifestEntry = this.loadSnapshotsManifest(snapshotsDir);
            }
        } catch (Exception e) {
            log.debug(Constants.D_LOG_SNAPSHOTS_DIR_RESOLVE_FAILED, consumerType, e.getMessage());
        }

        // The effective catalog URI prefers, in order:
        //   1. the configured setting `plugins.content_manager.catalog.<type>`,
        //   2. the plan's feature resource (registered environments only),
        //   3. the existing consumer doc's `resource` (auto-recovery on second+ runs),
        //   4. the manifest entry's `resource` (auto-recovery on the first sync after the local
        //      snapshot was consumed/deleted, when no doc exists yet).
        String settingCatalogUri = this.getCustomCatalogUri();
        // A registered instance whose plan could not be fetched has an unknown plan, not a free one:
        // it keeps its current data source and must not be downgraded below.
        String planResource = null;
        boolean planUnknown = false;
        try {
            planResource = pass.planResource(consumerType);
        } catch (CtiConsoleUnavailableException e) {
            // An offline pass does not look the plan up on purpose; nothing failed.
            if (!pass.isOffline()) {
                log.warn(Constants.W_LOG_PLAN_RESOURCE_RESOLVE_FAILED, consumerType, e.getMessage());
            }
            planUnknown = true;
        }
        String existingResource = this.readExistingConsumerResource(consumerType);
        String manifestResource =
                (manifestEntry != null
                                && manifestEntry.has(Constants.KEY_RESOURCE)
                                && !manifestEntry.get(Constants.KEY_RESOURCE).isNull())
                        ? manifestEntry.get(Constants.KEY_RESOURCE).asText("")
                        : "";
        String catalogUri;
        if (settingCatalogUri != null && !settingCatalogUri.isBlank()) {
            catalogUri = settingCatalogUri;
        } else if (planResource != null && !planResource.isBlank()) {
            catalogUri = planResource;
        } else if (existingResource != null && !existingResource.isBlank()) {
            catalogUri = existingResource;
        } else if (!manifestResource.isBlank()) {
            catalogUri = manifestResource;
        } else {
            catalogUri = null;
        }

        // When the plan provides a different resource than the existing consumer, the consumer moves
        // to it through a blue/green swap instead of wiping live indices: the ShadowSwapService
        // downloads into hidden staging indices and switches the aliases of every moving consumer
        // at once.
        //
        // Two cases trigger a swap:
        //   1. Upgrade: planResource is non-null and differs from existingResource.
        //   2. Downgrade: the environment has no plan resource (unregistered, token rejected, or the
        //      plan has no feature for this consumer), but existingResource differs from the
        //      manifest resource (free/default). This means we were on a paid plan and need to swap
        //      back to free content. Never taken when the plan lookup failed (planUnknown): a CTI
        //      outage must not downgrade a paying instance.
        String swapTargetResource = null;
        if (planResource != null
                && !planResource.isBlank()
                && existingResource != null
                && !existingResource.isBlank()
                && !UrlUtils.isSameResource(planResource, existingResource)) {
            // Case 1: Plan upgrade or cross-plan change.
            log.debug(Constants.D_LOG_INDEX_SWAP_STARTED, consumerType, existingResource, planResource);
            swapTargetResource = planResource;
            catalogUri = planResource;
        } else if (!planUnknown
                && (planResource == null || planResource.isBlank())
                && existingResource != null
                && !existingResource.isBlank()
                && !manifestResource.isBlank()
                && !UrlUtils.isSameResource(existingResource, manifestResource)) {
            // Case 2: Downgrade to free — existing resource is a paid URL, manifest has the
            // free/default URL. Swap to the manifest content.
            log.debug(
                    Constants.D_LOG_INDEX_SWAP_TO_FREE_PLAN,
                    consumerType,
                    existingResource,
                    manifestResource);
            swapTargetResource = manifestResource;
            catalogUri = manifestResource;
        }
        return new ContentSource(
                snapshotsDir, localSnapshot, manifestEntry, catalogUri, swapTargetResource);
    }

    /**
     * Performs the core synchronization logic for consumer services. Retrieves local and remote
     * consumer state, creates any missing indices with their mappings and aliases, initializes from
     * snapshot if this is a first-time sync (offset = 0), and applies incremental updates if the
     * remote offset is ahead.
     *
     * @param pass The pass this synchronization belongs to.
     * @return a {@link SyncResult} carrying whether content was updated and whether a configured feed
     *     could not be reached.
     */
    private SyncResult syncConsumerServices(SyncPass pass) {
        String consumerType = this.getConsumerType();
        ContentSource source = pass.contentSource(consumerType);
        if (source == null) {
            source = this.resolveContentSource(pass);
            pass.recordContentSource(consumerType, source);
        }
        if (source.changes() && pass.swapOutcome(consumerType) != SyncPass.SwapOutcome.SWAPPED) {
            // Only a swap of every changing consumer at once moves a data source, so that readers
            // never see two plans mixed. Until one succeeds, the current content stays as it is.
            log.debug(Constants.D_LOG_SOURCE_CHANGE_PENDING, consumerType);
            this.setConsumerStatus(LocalConsumer.Status.RUNNING);
            return new SyncResult(false, false, false, true);
        }
        Path snapshotsDir = source.snapshotsDir();
        Path localSnapshot = source.localSnapshot();
        JsonNode manifestEntry = source.manifestEntry();
        String catalogUri = source.catalogUri();

        String context = PluginSettings.getContextFromCatalogUri(catalogUri);
        String consumer = PluginSettings.getConsumerFromCatalogUri(catalogUri);

        // Build URL resolver based on registration status
        ResourceUrlResolver urlResolver;
        TokenExchangeServiceImpl tokenExchangeService = null;
        if (PluginSettings.getInstance().isRegistered()) {
            log.debug(Constants.D_LOG_SIGNED_URL_RESOLVER, consumerType);
            tokenExchangeService = new TokenExchangeServiceImpl();
            urlResolver =
                    new SignedUrlResolver(
                            tokenExchangeService, PluginSettings.getInstance().getAccessToken());
        } else {
            log.debug(Constants.D_LOG_REGULAR_URL_RESOLVER, consumerType);
            urlResolver = new RegularUrlResolver();
        }
        try {

            LocalConsumer localConsumer;
            boolean catalogConfigured = catalogUri != null && !catalogUri.isBlank();
            RemoteConsumer remoteConsumer;
            ConsumerServiceImpl ownedConsumerService = null;
            try {
                ConsumerService consumerService;
                if (this.consumerServiceOverride != null) {
                    consumerService = this.consumerServiceOverride;
                } else {
                    ownedConsumerService =
                            new ConsumerServiceImpl(
                                    context,
                                    consumer,
                                    consumerType,
                                    catalogUri,
                                    this.consumersIndex,
                                    new ApiClient(urlResolver));
                    consumerService = ownedConsumerService;
                }
                localConsumer = consumerService.getLocalConsumer();
                // An offline pass loads the snapshot files placed on this node and never asks CTI.
                remoteConsumer =
                        catalogConfigured && !pass.isOffline() ? consumerService.getRemoteConsumer() : null;
            } finally {
                if (ownedConsumerService != null) {
                    ownedConsumerService.close();
                }
            }

            // A configured catalog whose remote consumer could not be fetched signals an unreachable
            // feed. The pass still completes (falling back to the local snapshot / applying no remote
            // changes), but the caller retries so a transiently-blocked feed recovers immediately.
            // getRemoteConsumer() swallows the network failure and returns null, so this is the only
            // place the unreachable-feed condition is observable.
            boolean feedUnreachable = catalogConfigured && remoteConsumer == null && !pass.isOffline();

            // Mark the pass as running before anything is applied. When the remote head is known, the
            // same write records the offset this pass syncs to, so that from the first running read
            // the document shows the gap still to be loaded instead of the offsets of the previous
            // pass. Only for the data source the document describes: the offsets of another one are
            // not comparable with its local offset.
            if (localConsumer != null
                    && remoteConsumer != null
                    && UrlUtils.isSameResource(localConsumer.getResource(), catalogUri)
                    && remoteConsumer.getOffset() >= localConsumer.getLocalOffset()
                    && remoteConsumer.getOffset() != localConsumer.getRemoteOffset()) {
                this.setConsumerStatus(LocalConsumer.Status.RUNNING, remoteConsumer.getOffset());
            } else {
                this.setConsumerStatus(LocalConsumer.Status.RUNNING);
            }

            Map<String, ContentIndex> indicesMap = new HashMap<>();
            for (Map.Entry<String, String> entry : this.getMappings().entrySet()) {
                String indexName = this.getIndexName(entry.getKey());
                indicesMap.put(entry.getKey(), new ContentIndex(this.client, indexName, entry.getValue()));
            }

            // The second of the two preconditions for downloading content: the Setup plugin reported
            // ready (checked by the caller) and this consumer's target indices exist. Nothing is
            // created here — the Setup plugin owns the threat-intel index topology. Downloading into a
            // missing index is what caused the defect this guard exists for: the writes below go
            // through the alias name, so OpenSearch would auto-create a concrete index there with
            // dynamic mappings, turning every declared keyword into a text field that can be neither
            // aggregated nor sorted on, and squatting the name the alias needs.
            List<String> missingIndices = this.missingTargetIndices();
            if (!missingIndices.isEmpty()) {
                log.error(Constants.E_LOG_SYNC_ABORTED_INDICES_MISSING, consumerType, missingIndices);
                return new SyncResult(false, feedUnreachable, true, false);
            }

            boolean updated = false;
            long currentOffset = localConsumer != null ? localConsumer.getLocalOffset() : 0;

            // Offset mismatch resilience
            if (localConsumer != null && remoteConsumer != null) {
                if (currentOffset > remoteConsumer.getOffset()) {
                    log.warn(
                            Constants.W_LOG_LOCAL_OFFSET_EXCEEDS_REMOTE,
                            currentOffset,
                            remoteConsumer.getOffset(),
                            consumerType);
                    currentOffset = 0;
                }
            }

            // Empty-index resilience. A non-zero offset says the content was already downloaded, so
            // only incremental changes would be applied and an empty index would stay empty. Reset the
            // offset so this pass reinitializes from a snapshot instead. This recovers the index the
            // Setup plugin had to delete because a dynamically mapped index was squatting its alias
            // name (see issue #1476), and any other case where the content is gone but the offset is
            // not. Restricted to single-index consumers (IoCs, CVEs), where an empty index is
            // unambiguous; the ruleset consumer spans six indices, of which some are legitimately
            // empty.
            if (currentOffset > 0 && this.getMappings().size() == 1) {
                String onlyIndex = indicesMap.values().iterator().next().getIndexName();
                if (this.isIndexEmpty(onlyIndex)) {
                    log.warn(Constants.W_LOG_EMPTY_INDEX_OFFSET_RESET, onlyIndex, currentOffset);
                    currentOffset = 0;
                }
            }

            // Offline update. An air-gapped deployment cannot fetch changes, so it is kept up to date
            // with newer snapshots placed in the snapshots directory, which a non-zero offset would
            // skip. A consumer with content is rebuilt from its file through a swap: the current
            // content, user content included, stays live until the file has loaded, and is kept if it
            // cannot be. A consumer without content takes the snapshot path below. Consumers without a
            // file are left as they are, instead of being reloaded from an older stable snapshot.
            if (pass.isOffline()
                    && currentOffset > 0
                    && localConsumer != null
                    && snapshotFileExists(localSnapshot)) {
                log.info(
                        Constants.I_LOG_OFFLINE_RELOAD,
                        consumerType,
                        localSnapshot.getFileName(),
                        currentOffset);
                if (this.rebuildFromSnapshotFile(localConsumer, localSnapshot)) {
                    currentOffset = this.readLocalOffset(consumerType);
                    updated = true;
                    log.info(Constants.I_LOG_OFFLINE_RELOADED, consumerType, currentOffset);
                } else {
                    log.error(
                            Constants.E_LOG_OFFLINE_RELOAD_FAILED, consumerType, localSnapshot.getFileName());
                }
            }

            if (currentOffset == 0) {
                boolean snapshotExists = snapshotFileExists(localSnapshot);

                boolean hasEffectiveCatalog = catalogUri != null && !catalogUri.isBlank();

                // t0: persist the initial consumer state (status=running, local_offset=0,
                // remote_offset=<latest known>) before snapshot loading begins, so external observers
                // can see the in-progress state. Identity fields come from the remote response when a
                // catalog URL is available (either setting or existing doc's resource), otherwise from
                // the manifest entry.
                this.writeInitialConsumer(remoteConsumer, manifestEntry, catalogUri, consumerType);
                // After t0, which writes the document afresh, and before anything is cleared or loaded.
                this.recordPhasesOwedByContentChange();

                SnapshotServiceImpl snapshotService =
                        this.snapshotServiceOverride != null
                                ? this.snapshotServiceOverride
                                : new SnapshotServiceImpl(
                                        consumerType,
                                        indicesMap,
                                        this.consumersIndex,
                                        this.environment,
                                        urlResolver,
                                        snapshotsDir,
                                        this.getSnapshotFilename());

                // When a catalog URL is available, prefer remote initialization and fall back to local
                // snapshot on failure. The catalog URL comes from the configured setting, or from a
                // previous run's persisted `resource` when the setting is empty.
                if (hasEffectiveCatalog
                        && remoteConsumer != null
                        && remoteConsumer.getSnapshotLink() != null) {
                    // Ruleset snapshots also affect Security Analytics/Space resources; other catalogs only
                    // clear indices.
                    if (this.isRulesetConsumer()) {
                        try {
                            SecurityAnalyticsService securityAnalyticsService =
                                    new SecurityAnalyticsServiceImpl(this.client);
                            CompletableFuture<Void> sapFuture = new CompletableFuture<>();
                            securityAnalyticsService.deleteSpaceResources(
                                    Space.STANDARD,
                                    ActionListener.wrap(
                                            r -> sapFuture.complete(null), sapFuture::completeExceptionally));
                            sapFuture.get(60, TimeUnit.SECONDS);

                            SpaceService spaceService = new SpaceService(this.client);
                            CompletableFuture<Void> spaceFuture = new CompletableFuture<>();
                            spaceService.deleteSpaceResources(
                                    Space.STANDARD,
                                    ActionListener.wrap(
                                            r -> spaceFuture.complete(null), spaceFuture::completeExceptionally));
                            spaceFuture.get(60, TimeUnit.SECONDS);
                        } catch (Exception e) {
                            log.error(Constants.E_LOG_CLEAR_RESOURCES_FAILED, consumerType, e.getMessage());
                        }
                    } else {
                        indicesMap.values().forEach(ContentIndex::clear);
                    }

                    log.debug(Constants.D_LOG_SNAPSHOT_INIT_CUSTOM_URL, catalogUri);
                    boolean remoteSuccess = snapshotService.initialize(remoteConsumer);
                    if (remoteSuccess) {
                        currentOffset = remoteConsumer.getSnapshotOffset();
                        updated = true;
                        if (snapshotExists) {
                            SnapshotServiceImpl.deleteSnapshot(localSnapshot);
                        }
                    } else {
                        // Three-tier fallback: stable snapshot -> packaged local -> give up
                        Path stableSnapshot = snapshotService.getStablePath();
                        boolean stableExists = false;
                        if (stableSnapshot != null) {
                            try {
                                final Path stableFinal = stableSnapshot;
                                stableExists =
                                        AccessController.doPrivilegedChecked(() -> Files.exists(stableFinal));
                            } catch (Exception e) {
                                log.debug(
                                        "Failed to check stable snapshot [{}]: {}", stableSnapshot, e.getMessage());
                            }
                        }

                        if (stableExists) {
                            log.warn(Constants.I_LOG_ROLLBACK_FROM_STABLE, consumerType, stableSnapshot);
                            boolean rollbackSuccess = snapshotService.initialize(stableSnapshot, manifestEntry);
                            if (rollbackSuccess) {
                                currentOffset = snapshotService.getMaxOffsetSeen();
                                updated = true;
                            } else if (snapshotExists) {
                                log.warn(Constants.W_LOG_STABLE_ROLLBACK_FAILED, consumerType, localSnapshot);
                                boolean localSuccess = snapshotService.initialize(localSnapshot, manifestEntry);
                                if (localSuccess) {
                                    currentOffset = snapshotService.getMaxOffsetSeen();
                                    updated = true;
                                } else {
                                    log.warn(Constants.W_LOG_LOCAL_SNAPSHOT_FALLBACK_FAILED, consumerType);
                                }
                            }
                        } else if (snapshotExists) {
                            log.warn(
                                    Constants.W_LOG_REMOTE_SNAPSHOT_FAILED_FALLBACK, consumerType, localSnapshot);
                            boolean localSuccess = snapshotService.initialize(localSnapshot, manifestEntry);
                            if (localSuccess) {
                                currentOffset = snapshotService.getMaxOffsetSeen();
                                updated = true;
                            } else {
                                log.warn(Constants.W_LOG_LOCAL_SNAPSHOT_FALLBACK_FAILED, consumerType);
                            }
                        } else {
                            log.warn(
                                    Constants.W_LOG_REMOTE_SNAPSHOT_FAILED_NO_LOCAL, consumerType, localSnapshot);
                        }
                    }
                } else if (snapshotExists) {
                    if (hasEffectiveCatalog && !pass.isOffline()) {
                        // Catalog URL was set but the remote attempt did not yield a usable response
                        // (invalid URL, network failure, missing snapshot link). Fall back to the
                        // packaged local snapshot.
                        log.warn(
                                Constants.W_LOG_CATALOG_UNREACHABLE_FALLBACK,
                                catalogUri,
                                consumerType,
                                localSnapshot.getFileName());
                    } else {
                        log.debug(
                                Constants.D_LOG_INIT_FROM_LOCAL_SNAPSHOT,
                                consumerType,
                                localSnapshot.getFileName());
                    }
                    boolean localSuccess = snapshotService.initialize(localSnapshot, manifestEntry);
                    if (localSuccess) {
                        currentOffset = snapshotService.getMaxOffsetSeen();
                        updated = true;
                    } else {
                        log.error(Constants.E_LOG_LOCAL_SNAPSHOT_INIT_FAILED, consumerType);
                    }
                } else {
                    Path stableSnapshot = snapshotService.getStablePath();
                    boolean stableExists = false;
                    if (stableSnapshot != null) {
                        try {
                            final Path stableFinal = stableSnapshot;
                            stableExists = AccessController.doPrivilegedChecked(() -> Files.exists(stableFinal));
                        } catch (Exception e) {
                            log.debug("Failed to check stable snapshot [{}]: {}", stableSnapshot, e.getMessage());
                        }
                    }

                    if (stableExists) {
                        log.info(Constants.I_LOG_ROLLBACK_FROM_STABLE, consumerType, stableSnapshot);
                        boolean rollbackSuccess = snapshotService.initialize(stableSnapshot, manifestEntry);
                        if (rollbackSuccess) {
                            currentOffset = snapshotService.getMaxOffsetSeen();
                            updated = true;
                        } else {
                            log.error(Constants.E_LOG_LOCAL_SNAPSHOT_INIT_FAILED, consumerType);
                        }
                    } else if (hasEffectiveCatalog) {
                        log.error(
                                Constants.E_LOG_INIT_FAILED_NO_LOCAL_NO_REMOTE_REACH, consumerType, localSnapshot);
                    } else {
                        log.error(
                                Constants.E_LOG_INIT_FAILED_NO_LOCAL_NO_REMOTE_CONFIG, consumerType, localSnapshot);
                    }
                }
            }

            if (updated && snapshotsDir != null) {
                this.broadcastSnapshotPromote(this.getSnapshotFilename());
            }

            // Incremental Update — skip when no snapshot was loaded and the gap spans the full
            // catalog, since fetching all changes incrementally from offset 0 will always exceed the
            // request timeout (issue #1383).
            if (remoteConsumer != null && currentOffset < remoteConsumer.getOffset()) {
                if (currentOffset == 0 && !updated) {
                    log.warn(
                            "Skipping incremental update for [{}]: no snapshot loaded,"
                                    + " full catalog gap [0 -> {}] would timeout",
                            consumerType,
                            remoteConsumer.getOffset());
                } else {
                    // Outside the try below: a failure to record must stop the pass, not be taken for
                    // a failed update and recovered from a snapshot.
                    this.recordPhasesOwedByContentChange();
                    try {
                        updated =
                                this.performIncrementalUpdate(
                                        context,
                                        consumer,
                                        consumerType,
                                        catalogUri,
                                        urlResolver,
                                        indicesMap,
                                        currentOffset,
                                        remoteConsumer.getOffset());
                    } catch (RuntimeException e) {
                        if (!this.updateFromSnapshotAfterFailure(
                                e,
                                context,
                                consumer,
                                consumerType,
                                catalogUri,
                                urlResolver,
                                indicesMap,
                                remoteConsumer,
                                currentOffset)) {
                            throw e;
                        }
                        updated = true;
                    }
                }
            }
            return new SyncResult(updated, feedUnreachable, false, false);
        } finally {
            if (tokenExchangeService != null) {
                tokenExchangeService.close();
            }
        }
    }

    /**
     * Recovers from an incremental update that stopped on a change that cannot be applied to the
     * stored content, such as a patch whose target does not exist or an update of a missing document.
     * That change fails the same way on every pass, so retrying it leaves the consumer stuck. If CTI
     * has a snapshot newer than the consumer's local offset, the content is rebuilt from it and the
     * remaining changes are applied from the snapshot's offset. A snapshot at or past the failing
     * offset already holds the change's result; an older one still rebuilds stored content that
     * diverged from CTI, which is what usually makes a valid change fail.
     *
     * <p>The snapshot is loaded through {@link #performShadowSwap}: into hidden staging indices, with
     * an atomic alias swap only once it has loaded, so the current content stays available while the
     * snapshot loads and is kept as it is if the snapshot cannot be loaded.
     *
     * <p>A given snapshot is used at most once: after it is loaded the local offset is at or past it,
     * so the same failure does not reload it on the next pass. Until CTI publishes a newer one, the
     * failure stands and later passes retry the change.
     *
     * @param failure The failure of the incremental update.
     * @param context The CTI context name.
     * @param consumer The CTI consumer name.
     * @param consumerType The consumer type identifier.
     * @param catalogUri The effective catalog URI.
     * @param urlResolver The URL resolver for API requests.
     * @param indicesMap The content indices keyed by type.
     * @param remoteConsumer The remote consumer, with the latest snapshot.
     * @param fromOffset The offset the failed update started from.
     * @return {@code true} if the content was updated from the snapshot, {@code false} if the failure
     *     must propagate.
     */
    private boolean updateFromSnapshotAfterFailure(
            RuntimeException failure,
            String context,
            String consumer,
            String consumerType,
            String catalogUri,
            ResourceUrlResolver urlResolver,
            Map<String, ContentIndex> indicesMap,
            RemoteConsumer remoteConsumer,
            long fromOffset) {
        ContentIndex.PatchException patchFailure =
                findCause(failure, ContentIndex.PatchException.class);
        if (patchFailure == null || patchFailure.getOffset() == null) {
            return false;
        }
        long failedOffset = patchFailure.getOffset();
        // The failed update may have checkpointed changes past the offset it started from.
        long localOffset = Math.max(fromOffset, this.readLocalOffset(consumerType));
        long snapshotOffset = remoteConsumer.getSnapshotOffset();
        String snapshotLink = remoteConsumer.getSnapshotLink();
        if (snapshotLink == null || snapshotLink.isBlank() || snapshotOffset <= localOffset) {
            log.warn(
                    Constants.W_LOG_NO_NEWER_SNAPSHOT_FOR_FAILED_OFFSET,
                    failedOffset,
                    consumerType,
                    localOffset,
                    snapshotOffset);
            return false;
        }

        log.warn(
                Constants.W_LOG_UPDATE_FROM_SNAPSHOT_AFTER_FAILURE,
                failedOffset,
                consumerType,
                snapshotOffset,
                localOffset);
        if (!this.performShadowSwap(catalogUri, remoteConsumer, urlResolver)) {
            log.error(Constants.E_LOG_UPDATE_FROM_SNAPSHOT_FAILED, consumerType, failedOffset);
            return false;
        }
        log.info(Constants.I_LOG_CONTENT_RELOADED_FROM_SNAPSHOT, consumerType, snapshotOffset);
        if (snapshotOffset < remoteConsumer.getOffset()) {
            this.performIncrementalUpdate(
                    context,
                    consumer,
                    consumerType,
                    catalogUri,
                    urlResolver,
                    indicesMap,
                    snapshotOffset,
                    remoteConsumer.getOffset());
        }
        return true;
    }

    /**
     * Reads the local offset persisted in the consumer document.
     *
     * @param consumerType The consumer type identifier.
     * @return The local offset, or 0 if the document is absent or unreadable.
     */
    private long readLocalOffset(String consumerType) {
        try {
            GetResponse response = this.consumersIndex.getConsumer(consumerType);
            if (response == null || !response.isExists()) {
                return 0;
            }
            return MAPPER.readValue(response.getSourceAsString(), LocalConsumer.class).getLocalOffset();
        } catch (Exception e) {
            log.debug(Constants.D_LOG_CONSUMER_RESOURCE_READ_FAILED, consumerType, e.getMessage());
            return 0;
        }
    }

    /**
     * Returns the first throwable of the given type in a cause chain.
     *
     * @param throwable The throwable to inspect.
     * @param type The type to look for.
     * @param <T> The type to look for.
     * @return The first match, or {@code null} if there is none.
     */
    private static <T extends Throwable> T findCause(Throwable throwable, Class<T> type) {
        for (Throwable cause = throwable; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause)) {
                return type.cast(cause);
            }
        }
        return null;
    }

    /**
     * Fetches and applies incremental changes from the CTI API between the given offsets and persists
     * the resulting consumer state. Shared by the regular sync path and the post-swap catch-up: a
     * swapped snapshot only carries data up to its snapshot offset, so the remaining changes up to
     * the remote head must be applied in the same pass. Failures propagate to the caller; {@link
     * UpdateServiceImpl#update} persists batch-level checkpoints so progress survives.
     *
     * @param context The CTI context name.
     * @param consumer The CTI consumer name.
     * @param consumerType The consumer type identifier.
     * @param catalogUri The effective catalog URI.
     * @param urlResolver The URL resolver for API requests.
     * @param indicesMap The content indices keyed by type.
     * @param fromOffset The offset to update from (exclusive).
     * @param toOffset The offset to update to (inclusive).
     * @return {@code true} if changes were applied.
     */
    // Package-private so tests can replace the calls to CTI.
    boolean performIncrementalUpdate(
            String context,
            String consumer,
            String consumerType,
            String catalogUri,
            ResourceUrlResolver urlResolver,
            Map<String, ContentIndex> indicesMap,
            long fromOffset,
            long toOffset) {
        log.info(Constants.I_LOG_UPDATING_CONSUMER_CONTENT, consumerType, fromOffset, toOffset);
        UpdateServiceImpl updateService =
                new UpdateServiceImpl(
                        context,
                        consumer,
                        consumerType,
                        catalogUri,
                        new ApiClient(urlResolver),
                        this.consumersIndex,
                        indicesMap);
        try {
            return updateService.update(fromOffset, toOffset);
        } finally {
            updateService.close();
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
    private JsonNode loadSnapshotsManifest(Path snapshotsDir) {
        Path manifestPath = snapshotsDir.resolve(Constants.MANIFEST_FILENAME);
        try {
            boolean exists = AccessController.doPrivilegedChecked(() -> Files.exists(manifestPath));
            if (!exists) {
                log.error(Constants.E_LOG_MANIFEST_NOT_FOUND, manifestPath);
                return null;
            }

            byte[] bytes = AccessController.doPrivilegedChecked(() -> Files.readAllBytes(manifestPath));
            JsonNode root = MAPPER.readTree(bytes);
            String snapshotFilename = this.getSnapshotFilename();
            JsonNode entry = root.get(snapshotFilename);
            if (entry == null || entry.isNull()) {
                log.error(
                        Constants.E_LOG_MANIFEST_ENTRY_MISSING, snapshotFilename, manifestPath.getFileName());
                return null;
            }
            log.debug(
                    Constants.D_LOG_SNAPSHOT_DETAILS_LOADED, snapshotFilename, manifestPath.getFileName());
            return entry;
        } catch (Exception e) {
            log.error(Constants.E_LOG_MANIFEST_READ_FAILED, manifestPath, e.getMessage());
            return null;
        }
    }

    /**
     * Broadcasts a snapshot-promote request to every node in the cluster so each node moves its local
     * packaged snapshot to the stable path. Fire-and-forget: failures are logged but do not block the
     * synchronization.
     *
     * @param snapshotFilename the snapshot filename to promote (e.g., "ruleset.zip").
     */
    private void broadcastSnapshotPromote(String snapshotFilename) {
        try {
            TransportPromoteSnapshotAction.NodesRequest request =
                    new TransportPromoteSnapshotAction.NodesRequest(snapshotFilename);
            this.client.execute(
                    PromoteSnapshotAction.INSTANCE,
                    request,
                    ActionListener.wrap(
                            response -> {
                                long succeeded =
                                        response.getNodes().stream()
                                                .filter(TransportPromoteSnapshotAction.NodeResponse::isSuccess)
                                                .count();
                                log.debug(
                                        Constants.D_LOG_SNAPSHOT_PROMOTE_BROADCAST_DONE,
                                        snapshotFilename,
                                        succeeded,
                                        response.failures().size());
                            },
                            e ->
                                    log.warn(
                                            Constants.W_LOG_SNAPSHOT_PROMOTE_BROADCAST_FAILED,
                                            snapshotFilename,
                                            e.getMessage())));
        } catch (Exception e) {
            log.warn(Constants.W_LOG_SNAPSHOT_PROMOTE_BROADCAST_FAILED, snapshotFilename, e.getMessage());
        }
    }

    /**
     * Rebuilds this consumer's content from a newer snapshot of the data source it is already on,
     * through {@link ShadowSwapService#rebuild}: the snapshot loads into hidden staging indices and
     * the aliases switch only once it has loaded, so the current content stays available meanwhile
     * and is kept if the snapshot cannot be loaded.
     *
     * @param resource The consumer's data source.
     * @param remoteConsumer The remote consumer metadata (with snapshot link and offset).
     * @param urlResolver The URL resolver for downloading content.
     * @return {@code true} if the rebuilt content is live, {@code false} if the current content was
     *     kept.
     */
    // Package-private so tests can replace the rebuild.
    boolean performShadowSwap(
            String resource, RemoteConsumer remoteConsumer, ResourceUrlResolver urlResolver) {
        if (remoteConsumer == null
                || remoteConsumer.getSnapshotLink() == null
                || remoteConsumer.getSnapshotLink().isBlank()) {
            log.error(Constants.E_LOG_SHADOW_SWAP_UNAVAILABLE, this.getConsumerType());
            return false;
        }
        return new ShadowSwapService(this.client, this.consumersIndex)
                .rebuild(this, resource, remoteConsumer, urlResolver);
    }

    /**
     * Prepares this consumer to move to a data source in a swap: its target indices must exist, and
     * the remote consumer of the data source must offer a snapshot to load.
     *
     * @param resource The data source the consumer moves to.
     * @return the swap candidate, or {@code null} if the consumer cannot move in this pass. The
     *     reason is logged.
     */
    ShadowSwapService.Candidate prepareSwap(String resource) {
        String consumerType = this.getConsumerType();
        List<String> missingIndices = this.missingTargetIndices();
        if (!missingIndices.isEmpty()) {
            log.error(Constants.E_LOG_SYNC_ABORTED_INDICES_MISSING, consumerType, missingIndices);
            return null;
        }
        ResourceUrlResolver urlResolver;
        TokenExchangeServiceImpl tokenExchangeService = null;
        if (PluginSettings.getInstance().isRegistered()) {
            log.debug(Constants.D_LOG_SIGNED_URL_RESOLVER, consumerType);
            tokenExchangeService = new TokenExchangeServiceImpl();
            urlResolver =
                    new SignedUrlResolver(
                            tokenExchangeService, PluginSettings.getInstance().getAccessToken());
        } else {
            log.debug(Constants.D_LOG_REGULAR_URL_RESOLVER, consumerType);
            urlResolver = new RegularUrlResolver();
        }
        boolean prepared = false;
        try {
            RemoteConsumer remoteConsumer = this.fetchRemoteConsumer(resource, urlResolver);
            if (remoteConsumer == null
                    || remoteConsumer.getSnapshotLink() == null
                    || remoteConsumer.getSnapshotLink().isBlank()) {
                log.error(Constants.E_LOG_SHADOW_SWAP_UNAVAILABLE, consumerType);
                return null;
            }
            prepared = true;
            return new ShadowSwapService.Candidate(
                    this, resource, remoteConsumer, urlResolver, tokenExchangeService);
        } finally {
            // A candidate closes the token exchange service once its swap ends.
            if (!prepared && tokenExchangeService != null) {
                tokenExchangeService.close();
            }
        }
    }

    /**
     * Fetches the remote consumer of a data source.
     *
     * @param resource The data source.
     * @param urlResolver The URL resolver for the request.
     * @return the remote consumer, or {@code null} if it could not be fetched.
     */
    private RemoteConsumer fetchRemoteConsumer(String resource, ResourceUrlResolver urlResolver) {
        if (this.consumerServiceOverride != null) {
            return this.consumerServiceOverride.getRemoteConsumer();
        }
        ConsumerServiceImpl consumerService =
                new ConsumerServiceImpl(
                        PluginSettings.getContextFromCatalogUri(resource),
                        PluginSettings.getConsumerFromCatalogUri(resource),
                        this.getConsumerType(),
                        resource,
                        this.consumersIndex,
                        new ApiClient(urlResolver));
        try {
            return consumerService.getRemoteConsumer();
        } finally {
            consumerService.close();
        }
    }

    /**
     * Loads the snapshot of a remote consumer into the staging indices of a swap. The consumer
     * document is left alone: it describes the live content, which this load does not change.
     *
     * @param stagingIndices The staging indices, keyed by type.
     * @param remoteConsumer The remote consumer, with the snapshot link.
     * @param urlResolver The URL resolver for the download.
     * @return {@code true} if the snapshot loaded in full.
     */
    // Package-private so tests can replace the download.
    boolean loadStagedSnapshot(
            Map<String, ContentIndex> stagingIndices,
            RemoteConsumer remoteConsumer,
            ResourceUrlResolver urlResolver) {
        SnapshotServiceImpl snapshotService =
                this.snapshotServiceOverride != null
                        ? this.snapshotServiceOverride
                        : SnapshotServiceImpl.forStaging(
                                this.getConsumerType(), stagingIndices, this.environment, urlResolver);
        return snapshotService.initialize(remoteConsumer);
    }

    /**
     * Rebuilds this consumer's content from a snapshot file on this node, through {@link
     * ShadowSwapService#rebuildFromFile}.
     *
     * @param current The consumer's document.
     * @param snapshot The snapshot file.
     * @return {@code true} if the rebuilt content is live, {@code false} if the current content was
     *     kept.
     */
    // Package-private so tests can replace the rebuild.
    boolean rebuildFromSnapshotFile(LocalConsumer current, Path snapshot) {
        return new ShadowSwapService(this.client, this.consumersIndex)
                .rebuildFromFile(this, current, snapshot);
    }

    /**
     * Loads a snapshot file into the staging indices of a swap. The file is left in place, and the
     * consumer document alone, as for {@link #loadStagedSnapshot}.
     *
     * @param stagingIndices The staging indices, keyed by type.
     * @param snapshot The snapshot file.
     * @return the highest offset in the file if it loaded in full, {@code -1} otherwise.
     */
    // Package-private so tests can replace the load.
    long loadStagedSnapshotFile(Map<String, ContentIndex> stagingIndices, Path snapshot) {
        SnapshotServiceImpl snapshotService =
                this.snapshotServiceOverride != null
                        ? this.snapshotServiceOverride
                        : SnapshotServiceImpl.forStaging(
                                this.getConsumerType(), stagingIndices, this.environment, new RegularUrlResolver());
        return snapshotService.initialize(snapshot, null) ? snapshotService.getMaxOffsetSeen() : -1;
    }

    /** Records that a swap replaced this consumer's content, see {@link #shadowSwapPerformed}. */
    void markShadowSwapPerformed() {
        this.shadowSwapPerformed = true;
    }
}
