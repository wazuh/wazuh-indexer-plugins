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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.resolve.ResolveIndexAction;
import org.opensearch.core.action.ActionListener;
import org.opensearch.env.Environment;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import com.wazuh.contentmanager.action.ReloadEngineContentAction;
import com.wazuh.contentmanager.action.ReloadEngineContentRequest;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Handles synchronization logic for the unified content consumer. Processes rules, decoders, kvdbs,
 * integrations, and policies. It also handles post-sync operations like creating detectors and
 * calculating policy hashes.
 */
public class ConsumerRulesetService extends AbstractConsumerService {

    private static final Logger log = LogManager.getLogger(ConsumerRulesetService.class);
    private static final String[] DOCUMENT_ONLY_SOURCE = new String[] {Constants.KEY_DOCUMENT};

    // Names of the SAP sync sub-phases that can independently fail and be retried on a later pass.
    // These are a persisted contract: they are stored in the pending_sync_phases field of the
    // .wazuh-cti-consumers document, so they are kept separate from the identically-spelled
    // Constants.KEY_* resource keys, which name REST payload fields and may evolve on their own.
    private static final String PHASE_INTEGRATIONS = "integrations";
    private static final String PHASE_RULES = "rules";
    private static final String PHASE_DETECTORS = "detectors";

    private final ObjectMapper mapper;

    private final SecurityAnalyticsService securityAnalyticsService;
    private final SpaceService spaceService;
    private final UserOverridesService userOverridesService;

    private Set<String> preSwapIntegrationIds = Collections.emptySet();
    private Set<String> preSwapRuleIds = Collections.emptySet();

    /**
     * Constructs a new UnifiedConsumerSynchronizer.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     * @param spaceService The shared space service.
     * @param securityAnalyticsService The shared SAP service.
     * @param userOverridesService The shared user overrides registry.
     */
    public ConsumerRulesetService(
            Client client,
            ConsumersIndex consumersIndex,
            Environment environment,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            UserOverridesService userOverridesService) {
        super(client, consumersIndex, environment);
        this.securityAnalyticsService = securityAnalyticsService;
        this.spaceService = spaceService;
        this.userOverridesService = userOverridesService;

        this.mapper = new ObjectMapper();
        this.mapper.setDefaultPropertyInclusion(JsonInclude.Include.ALWAYS);
        this.mapper
                .configOverride(Policy.class)
                .setInclude(
                        JsonInclude.Value.construct(JsonInclude.Include.ALWAYS, JsonInclude.Include.ALWAYS));
    }

    @Override
    protected String getConsumerType() {
        return Constants.CONSUMER_TYPE_RULESET;
    }

    @Override
    protected String getCustomCatalogUri() {
        return PluginSettings.getInstance().getCatalogRuleset();
    }

    @Override
    protected boolean isRulesetConsumer() {
        return true;
    }

    @Override
    protected boolean hasUserContent() {
        return true;
    }

    @Override
    protected void onBeforeAliasSwap() {
        try {
            this.preSwapIntegrationIds =
                    this.spaceService.getResourceIdsBySpace(Constants.INDEX_INTEGRATIONS, Space.STANDARD);
        } catch (Exception e) {
            log.warn("Failed to collect pre-swap integration IDs: {}", e.getMessage());
            this.preSwapIntegrationIds = Collections.emptySet();
        }
        try {
            this.preSwapRuleIds =
                    this.spaceService.getResourceIdsBySpace(Constants.INDEX_RULES, Space.STANDARD);
        } catch (Exception e) {
            log.warn("Failed to collect pre-swap rule IDs: {}", e.getMessage());
            this.preSwapRuleIds = Collections.emptySet();
        }
    }

    @Override
    protected String getSnapshotFilename() {
        return Constants.CONTENT_SNAPSHOT_FILENAME;
    }

    /**
     * Returns the mappings configuration for the indices handled by this synchronizer.
     *
     * @return A map where keys are resource types and values are mapping file paths.
     */
    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(Constants.KEY_RULE, Constants.MAPPING_RULES);
        mappings.put(Constants.KEY_DECODER, Constants.MAPPING_DECODERS);
        mappings.put(Constants.KEY_KVDB, Constants.MAPPING_KVDBS);
        mappings.put(Constants.KEY_INTEGRATION, Constants.MAPPING_INTEGRATIONS);
        mappings.put(Constants.KEY_POLICY, Constants.MAPPING_POLICIES);
        mappings.put(Constants.KEY_FILTER, Constants.MAPPING_FILTERS);
        return mappings;
    }

    /**
     * Triggered when the primary synchronization is finished. Refreshes indices, initializes spaces,
     * and synchronizes SAP resources.
     *
     * @param isUpdated Indicates if the content was updated during sync.
     */
    @Override
    public void onSyncComplete(boolean isUpdated) {
        this.initializeSpaces();

        List<String> pendingPhases = this.readPendingSyncPhases();
        boolean createDetectors = PluginSettings.getInstance().getCreateDetectors();

        boolean shouldSyncIntegrations = isUpdated || pendingPhases.contains(PHASE_INTEGRATIONS);
        boolean shouldSyncRules = isUpdated || pendingPhases.contains(PHASE_RULES);
        boolean shouldSyncDetectors =
                createDetectors && (isUpdated || pendingPhases.contains(PHASE_DETECTORS));

        if (!shouldSyncIntegrations && !shouldSyncRules && !shouldSyncDetectors) {
            // Reaching this point with "detectors" still pending means detector creation is disabled,
            // so the phase can never be retried: drop it rather than re-reading it on every pass
            // forever. Every other path rebuilds the pending list from scratch below.
            if (pendingPhases.contains(PHASE_DETECTORS)) {
                this.setPendingSyncPhases(
                        pendingPhases.stream().filter(phase -> !PHASE_DETECTORS.equals(phase)).toList());
            }
            return;
        }

        if (isUpdated) {
            this.refreshIndices(
                    Constants.INDEX_RULES,
                    Constants.INDEX_DECODERS,
                    Constants.INDEX_KVDBS,
                    Constants.INDEX_INTEGRATIONS,
                    Constants.INDEX_POLICIES);

            // Re-apply the user's overrides before anything reads the rebuilt content. The Security
            // Analytics sync below, the space hash and the engine payload must all see the merged
            // values, not the ones CTI just wrote. This one hook covers every path that gets here --
            // full resync, rollback to a snapshot, incremental patches and a plan change.
            //
            // A failure must not abort the sync: the registry is a durable document, so the worst case
            // is that the overrides are re-applied one synchronization later. Unlike the integrations'
            // pre-snapshot capture, there is nothing here that is about to be destroyed.
            try {
                this.<Void>awaitResult(l -> this.userOverridesService.apply(Space.STANDARD.toString(), l));
            } catch (IOException e) {
                log.error(Constants.E_LOG_USER_OVERRIDES_REGISTRY_READ_FAILED, e.getMessage());
            }
        }

        List<String> stillPending = new ArrayList<>();

        // Integrations and detectors are both built from the integration documents, so read them
        // once for whichever of the two phases is due this pass.
        Map<String, JsonNode> integrationDocs = Collections.emptyMap();
        boolean integrationDocsRead = false;
        if (shouldSyncIntegrations || shouldSyncDetectors) {
            IntegrationDocsResult read = this.readIntegrationDocs();
            integrationDocs = read.docs();
            integrationDocsRead = read.ok();
        }

        // Sync Integrations
        if (shouldSyncIntegrations) {
            try {
                if (!integrationDocsRead || !this.pushIntegrations(integrationDocs)) {
                    stillPending.add(PHASE_INTEGRATIONS);
                }
            } catch (Exception e) {
                log.error(Constants.E_LOG_SAP_SYNC_FAILED, PHASE_INTEGRATIONS, e.getMessage(), e);
                stillPending.add(PHASE_INTEGRATIONS);
            }
        }

        // Sync Rules
        if (shouldSyncRules) {
            try {
                if (!this.syncRules()) {
                    stillPending.add(PHASE_RULES);
                }
            } catch (Exception e) {
                log.error(Constants.E_LOG_SAP_SYNC_FAILED, PHASE_RULES, e.getMessage(), e);
                stillPending.add(PHASE_RULES);
            }
        }

        // Sync Detectors (reuses the integration docs already read above)
        if (shouldSyncDetectors) {
            if (!integrationDocsRead) {
                // syncDetectors() cannot tell an empty map apart from "no detectors to create", so
                // it would report success and this phase would be cleared without having created
                // anything. readIntegrationDocs() already logged why the read failed.
                log.debug(Constants.D_LOG_SAP_DETECTORS_NO_INTEGRATIONS);
                stillPending.add(PHASE_DETECTORS);
            } else {
                try {
                    if (!this.syncDetectors(integrationDocs)) {
                        stillPending.add(PHASE_DETECTORS);
                    }
                } catch (Exception e) {
                    log.error(Constants.E_LOG_SAP_SYNC_FAILED, PHASE_DETECTORS, e.getMessage(), e);
                    stillPending.add(PHASE_DETECTORS);
                }
            }
        }

        // Only write when the set of pending phases actually changed. Persisting it costs a cluster
        // health check plus an immediate-refresh index request, and both the healthy case (nothing
        // pending before or after) and a permanently degraded one (the same phases failing every
        // pass) would otherwise pay that on every scheduled sync.
        if (!stillPending.equals(pendingPhases)) {
            this.setPendingSyncPhases(stillPending);
        }
        if (!stillPending.isEmpty()) {
            log.error(Constants.E_LOG_SAP_SYNC_DEGRADED, this.getConsumerType(), stillPending);
        }

        if (this.shadowSwapPerformed) {
            this.deleteStaleResources();
            this.shadowSwapPerformed = false;
        }

        if (isUpdated) {
            // Reload STANDARD space, as it was updated.
            try {
                this.<Set<String>>awaitResult(
                        l -> this.spaceService.calculateAndUpdate(List.of(Space.STANDARD.toString()), l));
            } catch (IOException e) {
                log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
            }
            // Broadcast a reload trigger to every node so each one loads the updated STANDARD space
            // into its own local Engine. A routine incremental update changes only index documents
            // (no cluster-state event), so peer nodes would otherwise not react until some unrelated
            // cluster-state event happened to fire their listener. The broadcast targets all nodes
            // including this one, and the per-node loader is hash-gated, so the call is idempotent
            // and a node that is down simply converges later via the cluster-state listener.
            this.client.execute(
                    ReloadEngineContentAction.INSTANCE,
                    new ReloadEngineContentRequest(),
                    ActionListener.wrap(
                            r -> log.debug(Constants.D_LOG_ENGINE_RELOAD_BROADCAST_SENT),
                            e -> log.warn(Constants.W_LOG_ENGINE_RELOAD_BROADCAST_FAILED, e.getMessage())));
        }
    }

    /**
     * Bridges an asynchronous {@link ActionListener}-based operation into a blocking call. Used only
     * on the background/generic sync thread, where blocking is permitted.
     *
     * @param <T> the result type
     * @param op consumer that starts the async operation with the supplied listener
     * @return the operation result
     * @throws IOException if the operation fails or times out
     */
    private <T> T awaitResult(Consumer<ActionListener<T>> op) throws IOException {
        CompletableFuture<T> future = new CompletableFuture<>();
        op.accept(ActionListener.wrap(future::complete, future::completeExceptionally));
        try {
            return future.get(60, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException io) {
                throw io;
            }
            throw new IOException(cause != null ? cause : e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        } catch (TimeoutException e) {
            throw new IOException(e);
        }
    }

    /**
     * Result of {@link #readIntegrationDocs()}.
     *
     * @param docs the extracted document nodes keyed by document ID, for use by {@link
     *     #pushIntegrations(Map)} and {@link #syncDetectors(Map)}.
     * @param ok {@code true} if the read completed, including when it legitimately found nothing to
     *     sync; {@code false} if the source index is missing or the read itself failed. Callers must
     *     not treat an empty {@code docs} as "nothing to sync" without checking this flag, or a
     *     failed read would mark the phase as done without anything having been sent.
     */
    private record IntegrationDocsResult(Map<String, JsonNode> docs, boolean ok) {}

    /**
     * Reads the Integrations from the internal index, without sending anything to Security Analytics.
     * Both the integrations phase and the detectors phase are built from these documents, so {@link
     * #onSyncComplete(boolean)} reads them once per pass.
     *
     * @return the extracted document nodes and whether the read completed.
     */
    private IntegrationDocsResult readIntegrationDocs() {
        Map<String, JsonNode> docs = new LinkedHashMap<>();

        if (this.indexIsMissing(Constants.INDEX_INTEGRATIONS)) {
            log.error(Constants.E_LOG_SAP_INDEX_MISSING, "Integrations", "integrations");
            return new IntegrationDocsResult(docs, false);
        }

        try {
            Map<String, Map<String, Object>> integrations =
                    this.awaitResult(
                            l ->
                                    this.spaceService.getResourcesBySpace(
                                            Constants.INDEX_INTEGRATIONS, Space.STANDARD, DOCUMENT_ONLY_SOURCE, l));
            if (integrations.isEmpty()) {
                log.debug(Constants.D_LOG_SAP_NOTHING_TO_SYNC, "integrations");
                return new IntegrationDocsResult(docs, true);
            }

            integrations.forEach(
                    (id, sourceMap) -> {
                        JsonNode doc = this.extractDocumentFromMap(sourceMap, id);
                        if (doc != null) {
                            docs.put(id, doc);
                        }
                    });
        } catch (Exception e) {
            log.error(Constants.E_LOG_SAP_SYNC_UNEXPECTED, "integrations", e.getMessage());
            return new IntegrationDocsResult(docs, false);
        }
        return new IntegrationDocsResult(docs, true);
    }

    /**
     * Sends already-read Integrations to the Security Analytics Plugin. Uses parallel execution with
     * a CountDownLatch to ensure all async requests complete.
     *
     * @param docs the integration document nodes to send, keyed by document ID, as read by {@link
     *     #readIntegrationDocs()}.
     * @return {@code true} if every integration was sent successfully, or there was nothing to send;
     *     {@code false} if at least one item failed, the wait timed out or the thread was
     *     interrupted.
     */
    private boolean pushIntegrations(Map<String, JsonNode> docs) {
        if (docs.isEmpty()) {
            return true;
        }

        boolean success = true;
        try {
            CountDownLatch latch = new CountDownLatch(docs.size());
            AtomicInteger sent = new AtomicInteger();
            List<String> failed = Collections.synchronizedList(new ArrayList<>());

            docs.forEach(
                    (id, doc) -> {
                        this.securityAnalyticsService.upsertIntegration(
                                doc,
                                Space.STANDARD,
                                RestRequest.Method.POST,
                                ActionListener.wrap(
                                        response -> {
                                            sent.incrementAndGet();
                                            latch.countDown();
                                        },
                                        e -> {
                                            failed.add(id);
                                            log.debug(Constants.D_LOG_SAP_ITEM_FAILED, "Integration", id, e.getMessage());
                                            latch.countDown();
                                        }));
                    });

            if (!latch.await(60, TimeUnit.SECONDS)) {
                log.warn(Constants.W_LOG_SAP_SYNC_TIMEOUT, "integrations");
                success = false;
            }
            if (sent.get() > 0) {
                log.info(
                        Constants.I_LOG_SAP_SUMMARY, sent.get(), docs.size(), "integrations", Space.STANDARD);
            }
            if (!failed.isEmpty()) {
                log.error(
                        Constants.E_LOG_SAP_PARTIAL, failed.size(), "integrations", Space.STANDARD, failed);
                success = false;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error(Constants.E_LOG_SAP_SYNC_INTERRUPTED, "integrations", e.getMessage());
            success = false;
        } catch (Exception e) {
            log.error(Constants.E_LOG_SAP_SYNC_UNEXPECTED, "integrations", e.getMessage());
            success = false;
        }
        return success;
    }

    /**
     * Synchronizes Rules from the internal index to the Security Analytics Plugin. Supports both
     * Standard and Custom rules.
     *
     * @return {@code true} if every rule was sent successfully (or there was nothing to sync); {@code
     *     false} if the source index is missing or at least one item failed.
     */
    private boolean syncRules() {
        if (this.indexIsMissing(Constants.INDEX_RULES)) {
            log.error(Constants.E_LOG_SAP_INDEX_MISSING, "Rules", "rules");
            return false;
        }

        try {
            Map<String, Map<String, Object>> rules =
                    this.awaitResult(
                            l ->
                                    this.spaceService.getResourcesBySpace(
                                            Constants.INDEX_RULES, Space.STANDARD, DOCUMENT_ONLY_SOURCE, l));
            if (rules.isEmpty()) {
                log.debug(Constants.D_LOG_SAP_NOTHING_TO_SYNC, "rules");
                return true;
            }

            Map<String, JsonNode> docs = new LinkedHashMap<>();
            rules.forEach(
                    (id, sourceMap) -> {
                        JsonNode doc = this.extractDocumentFromMap(sourceMap, id);
                        if (doc != null) {
                            docs.put(id, doc);
                        }
                    });

            if (docs.isEmpty()) {
                return true;
            }

            CountDownLatch latch = new CountDownLatch(docs.size());
            AtomicInteger sent = new AtomicInteger();
            List<String> failed = Collections.synchronizedList(new ArrayList<>());

            docs.forEach(
                    (id, doc) -> {
                        this.securityAnalyticsService.upsertRule(
                                doc,
                                Space.STANDARD,
                                RestRequest.Method.POST,
                                ActionListener.wrap(
                                        response -> {
                                            sent.incrementAndGet();
                                            latch.countDown();
                                        },
                                        e -> {
                                            failed.add(id);
                                            log.debug(Constants.D_LOG_SAP_ITEM_FAILED, "Rule", id, e.getMessage());
                                            latch.countDown();
                                        }));
                    });

            boolean success = true;
            if (!latch.await(60, TimeUnit.SECONDS)) {
                log.warn(Constants.W_LOG_SAP_SYNC_TIMEOUT, "rules");
                success = false;
            }
            if (sent.get() > 0) {
                log.info(Constants.I_LOG_SAP_SUMMARY, sent.get(), docs.size(), "rules", Space.STANDARD);
            }
            if (!failed.isEmpty()) {
                log.error(Constants.E_LOG_SAP_PARTIAL, failed.size(), "rules", Space.STANDARD, failed);
                success = false;
            }
            return success;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error(Constants.E_LOG_SAP_SYNC_INTERRUPTED, "rules", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error(Constants.E_LOG_SAP_SYNC_UNEXPECTED, "rules", e.getMessage());
            return false;
        }
    }

    /**
     * Synchronizes Threat Detectors to the Security Analytics Plugin. The first detector is created
     * sequentially to ensure the SAP detectors config index exists, then the remaining detectors are
     * created in parallel.
     *
     * @param integrationDocs the integration document nodes already extracted by {@link
     *     #readIntegrationDocs()}, keyed by document ID. Callers must only pass the documents of a
     *     read that completed: an empty map is reported as success ("no detectors to create"), so a
     *     failed read would silently look like a successful sync.
     * @return {@code true} if every detector was sent successfully (or there was nothing to sync);
     *     {@code false} if required source indices are missing or at least one item failed.
     */
    private boolean syncDetectors(Map<String, JsonNode> integrationDocs) {
        if (!(this.securityAnalyticsService instanceof SecurityAnalyticsServiceImpl sapService)) {
            return true;
        }
        // One read for every detector: the user's decisions live in a single registry document.
        Map<String, Boolean> detectorOverrides = new HashMap<>();
        try {
            UserOverrides overrides =
                    this.<UserOverrides>awaitResult(
                            l -> this.userOverridesService.read(Space.STANDARD.toString(), l));
            overrides
                    .getIntegrations()
                    .forEach(
                            override -> {
                                if (override.getDetectorEnabled() != null) {
                                    detectorOverrides.put(override.getId(), override.getDetectorEnabled());
                                }
                            });
        } catch (IOException e) {
            // Without the overrides every detector falls back to CTI's default, which is the state the
            // next sync will correct. Aborting here would leave the space without detectors instead.
            log.error(Constants.E_LOG_USER_OVERRIDES_REGISTRY_READ_FAILED, e.getMessage());
        }

        List<JsonNode> docs = new ArrayList<>();
        integrationDocs.forEach(
                (id, doc) -> {
                    if (sapService.buildDetectorRequest(doc, true, detectorOverrides.get(id)) != null) {
                        docs.add(doc);
                    }
                });

        if (docs.isEmpty()) {
            return true;
        }

        // detectors reference the wazuh-events-v5-* data streams as source indices, and Security
        // Analytics rejects detectors whose source indices do not exist.
        List<String> missingIndices = this.missingSourceIndices(docs);
        if (!missingIndices.isEmpty()) {
            log.error(
                    "Skipping detectors sync. Required source indices not found: {}",
                    String.join(", ", missingIndices));
            return false;
        }

        log.debug(Constants.D_LOG_SAP_DETECTORS_SYNCING, docs.size(), 1, docs.size() - 1);

        AtomicInteger sent = new AtomicInteger();
        List<String> failed = Collections.synchronizedList(new ArrayList<>());

        // Process the first detector sequentially to ensure the config index is created
        CountDownLatch firstLatch = new CountDownLatch(1);
        JsonNode firstDoc = docs.getFirst();
        String firstName = this.detectorTitle(firstDoc);
        this.securityAnalyticsService.upsertDetectorAsync(
                firstDoc,
                true,
                RestRequest.Method.POST,
                detectorOverrides.get(firstDoc.path(Constants.KEY_ID).asText()),
                ActionListener.wrap(
                        response -> {
                            sent.incrementAndGet();
                            firstLatch.countDown();
                        },
                        e -> {
                            failed.add(firstName);
                            log.debug(
                                    Constants.D_LOG_SAP_ITEM_FAILED,
                                    "Detector for integration",
                                    firstName,
                                    e.getMessage());
                            firstLatch.countDown();
                        }));

        try {
            if (!firstLatch.await(30, TimeUnit.SECONDS)) {
                log.warn(Constants.W_LOG_SAP_SYNC_TIMEOUT, "detectors");
                return false;
            }
        } catch (InterruptedException e) {
            log.error(Constants.E_LOG_DETECTOR_WAIT_INTERRUPTED, e);
            Thread.currentThread().interrupt();
            return false;
        }

        // Process remaining detectors in parallel
        boolean timedOut = false;
        if (docs.size() > 1) {
            CountDownLatch parallelLatch = new CountDownLatch(docs.size() - 1);
            for (int i = 1; i < docs.size(); i++) {
                JsonNode doc = docs.get(i);
                String name = this.detectorTitle(doc);
                this.securityAnalyticsService.upsertDetectorAsync(
                        doc,
                        true,
                        RestRequest.Method.POST,
                        detectorOverrides.get(doc.path(Constants.KEY_ID).asText()),
                        ActionListener.wrap(
                                response -> {
                                    sent.incrementAndGet();
                                    parallelLatch.countDown();
                                },
                                e -> {
                                    failed.add(name);
                                    log.debug(
                                            Constants.D_LOG_SAP_ITEM_FAILED,
                                            "Detector for integration",
                                            name,
                                            e.getMessage());
                                    parallelLatch.countDown();
                                }));
            }

            try {
                if (!parallelLatch.await(60, TimeUnit.SECONDS)) {
                    log.warn(Constants.W_LOG_SAP_SYNC_TIMEOUT, "detectors");
                    timedOut = true;
                }
            } catch (InterruptedException e) {
                log.error(Constants.E_LOG_DETECTOR_WAIT_INTERRUPTED, e);
                Thread.currentThread().interrupt();
                timedOut = true;
            }
        }

        // One INFO summary instead of one line per item (per-item sends are at
        // DEBUG); skipped entirely when nothing was sent to keep no-op syncs quiet.
        if (sent.get() > 0) {
            log.info(Constants.I_LOG_SAP_SUMMARY, sent.get(), docs.size(), "detectors", Space.STANDARD);
        }
        if (!failed.isEmpty()) {
            log.error(Constants.E_LOG_SAP_PARTIAL, failed.size(), "detectors", Space.STANDARD, failed);
        }
        return !timedOut && failed.isEmpty();
    }

    /**
     * Deletes SAP integrations, detectors and rules that existed before a shadow swap but are no
     * longer present in the new subscription content. Called after new resources have been upserted
     * so that detectors keep running during the transition.
     */
    private void deleteStaleResources() {
        try {
            Set<String> currentIntegrationIds =
                    this.spaceService.getResourceIdsBySpace(Constants.INDEX_INTEGRATIONS, Space.STANDARD);
            Set<String> staleIntegrationIds = new HashSet<>(this.preSwapIntegrationIds);
            staleIntegrationIds.removeAll(currentIntegrationIds);

            if (!staleIntegrationIds.isEmpty()) {
                CountDownLatch integrationLatch = new CountDownLatch(staleIntegrationIds.size());
                for (String id : staleIntegrationIds) {
                    this.securityAnalyticsService.deleteIntegration(
                            id,
                            Space.STANDARD,
                            ActionListener.wrap(
                                    r -> integrationLatch.countDown(),
                                    e -> {
                                        log.warn("Failed to delete stale integration [{}]: {}", id, e.getMessage());
                                        integrationLatch.countDown();
                                    }));
                }
                integrationLatch.await(120, TimeUnit.SECONDS);
            }

            Set<String> currentRuleIds =
                    this.spaceService.getResourceIdsBySpace(Constants.INDEX_RULES, Space.STANDARD);
            Set<String> staleRuleIds = new HashSet<>(this.preSwapRuleIds);
            staleRuleIds.removeAll(currentRuleIds);

            if (!staleRuleIds.isEmpty()) {
                CountDownLatch ruleLatch = new CountDownLatch(staleRuleIds.size());
                for (String id : staleRuleIds) {
                    this.securityAnalyticsService.deleteRule(
                            id,
                            Space.STANDARD,
                            ActionListener.wrap(
                                    r -> ruleLatch.countDown(),
                                    e -> {
                                        log.warn("Failed to delete stale rule [{}]: {}", id, e.getMessage());
                                        ruleLatch.countDown();
                                    }));
                }
                ruleLatch.await(120, TimeUnit.SECONDS);
            }

            if (!staleIntegrationIds.isEmpty() || !staleRuleIds.isEmpty()) {
                log.info(
                        "Deleted {} stale integration(s) and {} stale rule(s) from SAP",
                        staleIntegrationIds.size(),
                        staleRuleIds.size());
            }
        } catch (Exception e) {
            log.error("Failed to clean up stale SAP resources: {}", e.getMessage(), e);
        } finally {
            this.preSwapIntegrationIds = Collections.emptySet();
            this.preSwapRuleIds = Collections.emptySet();
        }
    }

    /**
     * Extracts the detector title from a document's metadata.
     *
     * @param doc The detector document.
     * @return The detector title, or "unknown" if it is not present.
     */
    private String detectorTitle(JsonNode doc) {
        return doc.has(Constants.KEY_METADATA)
                        && doc.get(Constants.KEY_METADATA).has(Constants.KEY_TITLE)
                ? doc.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText()
                : "unknown";
    }

    /**
     * Creates default policy documents for user spaces (draft, testing, custom) if they don't exist.
     */
    private void initializeSpaces() {
        try {
            this.<Void>awaitResult(l -> this.spaceService.initializeDefaultSpaces(l));
        } catch (IOException e) {
            log.error(Constants.E_LOG_INITIALIZE_SPACE_FAILED, "spaces", e.getMessage());
        }
    }

    /**
     * Collects the detector source indices declared in the given integration documents and returns
     * those that do not exist in the cluster.
     *
     * @param docs integration documents potentially holding a {@code detector.source} array.
     * @return sorted list of missing source indices; empty if all exist.
     */
    List<String> missingSourceIndices(List<JsonNode> docs) {
        Set<String> sourceIndices = new TreeSet<>();
        for (JsonNode doc : docs) {
            JsonNode detector = doc.path(Constants.KEY_DETECTOR);
            if (detector.has(Constants.KEY_SOURCE) && detector.get(Constants.KEY_SOURCE).isArray()) {
                detector.get(Constants.KEY_SOURCE).forEach(source -> sourceIndices.add(source.asText()));
            }
        }

        List<String> missing = new ArrayList<>();
        for (String index : sourceIndices) {
            if (this.indexIsMissing(index)) {
                missing.add(index);
            }
        }
        return missing;
    }

    /**
     * Checks if the specified index exists in the cluster. Uses the resolve index API so the name may
     * be a plain index, an alias or a data stream (the indices exists API does not resolve data
     * streams, which would report the wazuh-events-v5-* streams as missing). Resolution failures are
     * treated as missing.
     *
     * @param indexName The name of the index, alias or data stream to check.
     * @return true if the name does not resolve to anything, false otherwise.
     */
    private boolean indexIsMissing(String indexName) {
        try {
            ResolveIndexAction.Request request = new ResolveIndexAction.Request(new String[] {indexName});
            ResolveIndexAction.Response response =
                    this.client.admin().indices().resolveIndex(request).actionGet();
            return response.getIndices().isEmpty()
                    && response.getAliases().isEmpty()
                    && response.getDataStreams().isEmpty();
        } catch (Exception e) {
            log.debug("Could not resolve index [{}]: {}", indexName, e.getMessage());
            return true;
        }
    }

    /**
     * Extracts the inner "document" object from the source wrapper.
     *
     * @param source The source JSON object (the wrapper containing metadata and the document).
     * @param hitId The ID of the hit, used for logging if the document field is missing.
     * @return The inner "document" {@link JsonNode}, or null if the key is missing.
     */
    private JsonNode extractDocument(JsonNode source, String hitId) {
        if (!source.has(Constants.KEY_DOCUMENT)) {
            log.warn(Constants.W_LOG_HIT_MISSING_DOCUMENT, hitId);
            return null;
        }
        return source.get(Constants.KEY_DOCUMENT);
    }

    /**
     * Extracts the inner "document" sub-map from a source map and converts only that sub-map to a
     * {@link JsonNode}, avoiding a full-source {@code valueToTree()} conversion.
     *
     * @param sourceMap The source map from the search hit.
     * @param hitId The ID of the hit, used for logging if the document field is missing.
     * @return The inner "document" as a {@link JsonNode}, or null if the key is missing.
     */
    private JsonNode extractDocumentFromMap(Map<String, Object> sourceMap, String hitId) {
        Object docObj = sourceMap.get(Constants.KEY_DOCUMENT);
        if (docObj == null) {
            log.warn(Constants.W_LOG_HIT_MISSING_DOCUMENT, hitId);
            return null;
        }
        return this.mapper.valueToTree(docObj);
    }
}
