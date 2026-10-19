/*
 * Copyright (C) 2026, Wazuh Inc.
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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.client.ResourceUrlResolver;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.index.IndexSwapHelper;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.console.service.TokenExchangeServiceImpl;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Replaces the content of consumers through a blue/green swap. The new content of each consumer is
 * built in hidden staging indices while its current content stays live, and then the aliases of all
 * of them switch in a single request. Readers see either the previous content of every consumer or
 * the new content of every consumer, never a mix.
 *
 * <p>Every consumer whose data source changes in a pass moves in the same swap, all or nothing:
 * when one of them cannot be prepared, the swap fails before the switch, or whether a consumer
 * changes data source cannot be determined, none of them switches and every consumer keeps its
 * current content.
 *
 * <p>From the moment a swap starts, the document of each moving consumer in {@code
 * .wazuh-cti-consumers} describes its new data source: its identity, status {@code running}, local
 * offset 0 and the remote offset of the new source. The documents of all moving consumers change in
 * one write, so readers see them change together. The local offset shows how much of the new
 * content is live: none until the switch, then the snapshot offset, then whatever the incremental
 * update that follows applies.
 *
 * <p>Such a document does not describe the live content, so a swap interrupted before the switch,
 * for instance by a node restart, must not be taken for a consumer that is already on its new data
 * source. The order of the writes keeps an interrupted swap recognizable: the staging indices are
 * created before the documents change, the local offset leaves 0 only after the switch, and a
 * failed swap restores the documents before deleting the staging indices. A document that is {@code
 * running} with local offset 0 while a staging index of the consumer exists therefore marks an
 * interrupted swap, and the next pass redoes it.
 */
public class ShadowSwapService {
    private static final Logger log = LogManager.getLogger(ShadowSwapService.class);

    private final Client client;
    private final ConsumersIndex consumersIndex;

    /**
     * Constructs a new ShadowSwapService.
     *
     * @param client The OpenSearch client used for index and alias operations.
     * @param consumersIndex The index holding the consumer documents.
     */
    public ShadowSwapService(Client client, ConsumersIndex consumersIndex) {
        this.client = client;
        this.consumersIndex = consumersIndex;
    }

    /**
     * Moves to its data source, in one swap, every consumer whose data source changes in this pass
     * and every consumer an interrupted pass left in the middle of a swap. When whether one of the
     * consumers changes data source cannot be determined, none of them moves. Records in the pass
     * what happened to each consumer.
     *
     * @param consumers The consumers of the pass.
     * @param pass The pass.
     */
    public void swapChangedSources(List<? extends AbstractConsumerService> consumers, SyncPass pass) {
        List<Request> requests = new ArrayList<>();
        List<String> undecided = new ArrayList<>();
        for (AbstractConsumerService consumer : consumers) {
            try {
                Request request = this.request(consumer, pass);
                if (request != null) {
                    requests.add(request);
                }
            } catch (Exception e) {
                log.warn(Constants.W_LOG_SWAP_DECISION_FAILED, consumer.getConsumerType(), e.getMessage());
                pass.recordSwapOutcome(consumer.getConsumerType(), SyncPass.SwapOutcome.HELD);
                undecided.add(consumer.getConsumerType());
            }
        }
        if (requests.isEmpty()) {
            return;
        }
        if (!undecided.isEmpty()) {
            // A consumer whose decision failed may be changing data source as well. Moving the others
            // without it would leave readers with the content of two plans, so none of them moves.
            log.warn(Constants.W_LOG_SWAP_POSTPONED_UNDECIDED, types(requests), undecided);
            this.recordOutcomes(requests, SwapResult.KEPT, pass);
            return;
        }

        List<Candidate> candidates = new ArrayList<>();
        List<String> unprepared = new ArrayList<>();
        SwapResult result = SwapResult.KEPT;
        try {
            for (Request request : requests) {
                Candidate candidate = this.prepare(request);
                if (candidate == null) {
                    unprepared.add(request.consumer.getConsumerType());
                } else {
                    candidates.add(candidate);
                }
            }
            if (unprepared.isEmpty()) {
                result = this.swap(candidates);
            } else {
                log.warn(Constants.W_LOG_SWAP_POSTPONED, types(requests), unprepared);
            }
        } finally {
            candidates.forEach(Candidate::close);
        }
        this.recordOutcomes(requests, result, pass);
    }

    /**
     * Records in the pass what a swap did to each consumer that was to move in it.
     *
     * @param requests The consumers that were to move.
     * @param result What the swap did to their content.
     * @param pass The pass.
     */
    private void recordOutcomes(List<Request> requests, SwapResult result, SyncPass pass) {
        for (Request request : requests) {
            SyncPass.SwapOutcome outcome;
            if (result == SwapResult.SWITCHED) {
                outcome = SyncPass.SwapOutcome.SWAPPED;
            } else if (result == SwapResult.KEPT && !request.interrupted) {
                outcome = SyncPass.SwapOutcome.PENDING;
            } else {
                // The document names the new data source while the live content is not, or is not
                // recorded as, the new one: only a swap may touch either of them.
                outcome = SyncPass.SwapOutcome.HELD;
            }
            pass.recordSwapOutcome(request.consumer.getConsumerType(), outcome);
        }
    }

    /**
     * Rebuilds the content of a consumer from a snapshot of the data source it is already on, through
     * staging indices like any swap, when its stored content can no longer be updated incrementally.
     * Its document is left alone until the switch, since it keeps describing the live content until
     * then.
     *
     * @param consumer The consumer.
     * @param resource The consumer's data source.
     * @param remoteConsumer The remote consumer, with the snapshot to load.
     * @param urlResolver The URL resolver for the download.
     * @return {@code true} if the rebuilt content is live, {@code false} if the current content was
     *     kept.
     */
    boolean rebuild(
            AbstractConsumerService consumer,
            String resource,
            RemoteConsumer remoteConsumer,
            ResourceUrlResolver urlResolver) {
        Candidate candidate = new Candidate(consumer, resource, remoteConsumer, urlResolver, null);
        candidate.rebuild = true;
        SwapResult result = this.swap(List.of(candidate));
        return result == SwapResult.SWITCHED || result == SwapResult.SWITCHED_UNRECORDED;
    }

    /**
     * Decides whether a consumer moves in this pass's swap, deleting any staging index a finished
     * swap left behind when it does not.
     *
     * @param consumer The consumer.
     * @param pass The pass.
     * @return the request, or {@code null} when the consumer stays on its data source.
     * @throws Exception if the consumer's document or indices cannot be read.
     */
    private Request request(AbstractConsumerService consumer, SyncPass pass) throws Exception {
        String type = consumer.getConsumerType();
        LocalConsumer document = consumer.readConsumerDocument();
        AbstractConsumerService.ContentSource source = consumer.resolveContentSource(pass);
        pass.recordContentSource(type, source);
        boolean interrupted = isMidSwap(document) && this.anyShadowIndexExists(consumer);
        if (source.changes()) {
            return new Request(consumer, source.swapTarget(), document, interrupted);
        }
        if (interrupted) {
            log.warn(Constants.W_LOG_SWAP_INTERRUPTED, type);
            return new Request(consumer, source.catalogUri(), document, true);
        }
        if (document != null && document.getLocalOffset() > 0) {
            this.deleteLeftovers(consumer);
        }
        return null;
    }

    /**
     * Prepares a consumer that moves in the swap.
     *
     * @param request The consumer's request.
     * @return the candidate, or {@code null} if the consumer cannot move in this pass. The reason is
     *     logged.
     */
    private Candidate prepare(Request request) {
        if (request.target == null || request.target.isBlank()) {
            log.error(Constants.E_LOG_SHADOW_SWAP_UNAVAILABLE, request.consumer.getConsumerType());
            return null;
        }
        Candidate candidate;
        try {
            candidate = request.consumer.prepareSwap(request.target);
        } catch (Exception e) {
            log.error(
                    Constants.E_LOG_SWAP_FAILED_BEFORE_SWITCH,
                    List.of(request.consumer.getConsumerType()),
                    e.getMessage());
            return null;
        }
        if (candidate != null) {
            candidate.before = request.document;
            candidate.interrupted = request.interrupted;
        }
        return candidate;
    }

    /**
     * Builds the new content of the candidates in staging indices and switches the aliases of all of
     * them in one request.
     *
     * @param candidates The consumers to swap.
     * @return what happened to the content.
     */
    private SwapResult swap(List<Candidate> candidates) {
        List<String> types = candidates.stream().map(Candidate::type).toList();
        boolean documentsChanged = false;
        try {
            // The staging indices go first: a moving consumer's document only changes while they
            // exist, which is what keeps an interrupted swap recognizable.
            for (Candidate candidate : candidates) {
                log.debug(Constants.D_LOG_SHADOW_INDICES_CREATING, candidate.type());
                Map<String, ContentIndex> staging = this.createStagingIndices(candidate.consumer);
                candidate.staging = staging;
                for (ContentIndex index : staging.values()) {
                    String alias = index.getIndexName();
                    candidate.aliasToStaging.put(alias, index.getPhysicalName());
                    candidate.aliasToLive.put(alias, this.livePhysicalName(alias));
                }
            }

            List<Candidate> moving = candidates.stream().filter(c -> !c.rebuild).toList();
            if (!moving.isEmpty()) {
                // Set before the write: a write that fails half way must be restored too.
                documentsChanged = true;
                this.consumersIndex.setConsumers(moving.stream().map(c -> c.document(0)).toList());
                moving.forEach(c -> log.info(Constants.I_LOG_CONTENT_SOURCE_CHANGED, c.type()));
            }

            for (Candidate candidate : candidates) {
                log.debug(
                        Constants.D_LOG_SHADOW_SNAPSHOT_DOWNLOADING, candidate.type(), candidate.resource);
                if (!candidate.consumer.loadStagedSnapshot(
                        candidate.staging, candidate.remoteConsumer, candidate.urlResolver)) {
                    log.error(Constants.E_LOG_SHADOW_SNAPSHOT_FAILED, candidate.type());
                    throw new IllegalStateException(
                            "the snapshot of consumer [" + candidate.type() + "] could not be loaded");
                }
            }

            for (Candidate candidate : candidates) {
                if (candidate.consumer.hasUserContent()) {
                    Map<String, String> liveToStaging = new LinkedHashMap<>();
                    candidate.aliasToStaging.forEach(
                            (alias, staging) -> liveToStaging.put(candidate.aliasToLive.get(alias), staging));
                    log.debug(Constants.D_LOG_REINDEX_USER_CONTENT, candidate.type());
                    this.copyUserContent(liveToStaging);
                }
            }

            for (Candidate candidate : candidates) {
                candidate.consumer.onBeforeAliasSwap();
            }

            Map<String, String> aliasToStaging = new LinkedHashMap<>();
            Map<String, String> aliasToLive = new LinkedHashMap<>();
            for (Candidate candidate : candidates) {
                aliasToStaging.putAll(candidate.aliasToStaging);
                aliasToLive.putAll(candidate.aliasToLive);
            }
            log.debug(Constants.D_LOG_REFRESH_STAGING_INDICES, types);
            this.refreshIndices(aliasToStaging.values());
            log.debug(Constants.D_LOG_ATOMIC_ALIAS_SWAP, types);
            this.switchAliases(aliasToStaging, aliasToLive);
            log.info(Constants.I_LOG_SWAP_SWITCHED, types, aliasToStaging.size());
        } catch (Exception e) {
            log.error(Constants.E_LOG_SWAP_FAILED_BEFORE_SWITCH, types, e.getMessage(), e);
            return this.rollBack(candidates, documentsChanged)
                    ? SwapResult.KEPT
                    : SwapResult.KEPT_UNRESTORED;
        }

        for (Candidate candidate : candidates) {
            candidate.consumer.markShadowSwapPerformed();
        }

        // The new content is live. Until its offsets are recorded, the documents of the moving
        // consumers still read local offset 0: the previous indices are then kept, so the next pass
        // redoes the swap instead of updating content its documents do not describe.
        try {
            this.consumersIndex.setConsumers(
                    candidates.stream().map(c -> c.document(c.remoteConsumer.getSnapshotOffset())).toList());
        } catch (Exception e) {
            log.error(Constants.E_LOG_SWAP_RECORDS_FAILED, types, e.getMessage());
            return SwapResult.SWITCHED_UNRECORDED;
        }
        for (Candidate candidate : candidates) {
            log.debug(
                    Constants.D_LOG_CONSUMER_DOC_REWRITTEN,
                    candidate.type(),
                    candidate.resource,
                    candidate.remoteConsumer.getSnapshotOffset());
            try {
                this.deleteIndices(candidate.aliasToLive.values());
            } catch (Exception e) {
                log.warn(Constants.W_LOG_OLD_INDICES_DELETE_FAILED, candidate.type(), e.getMessage());
            }
            if (!candidate.rebuild) {
                log.info(Constants.I_LOG_CONTENT_UPDATED_NEW_SOURCE, candidate.type());
            }
        }
        return SwapResult.SWITCHED;
    }

    /**
     * Undoes a swap that failed before the switch: restores the documents of the moving consumers,
     * then deletes their staging indices. A consumer whose document cannot be restored, or was
     * already in the middle of an interrupted swap, keeps its staging indices: they are what marks
     * its swap as interrupted, so the next pass redoes it.
     *
     * @param candidates The consumers of the failed swap.
     * @param documentsChanged Whether the documents of the moving consumers were written.
     * @return {@code true} if the documents describe the kept content again, {@code false} if they
     *     could not be restored.
     */
    private boolean rollBack(List<Candidate> candidates, boolean documentsChanged) {
        if (documentsChanged) {
            List<LocalConsumer> before =
                    candidates.stream()
                            .filter(c -> !c.rebuild && c.before != null)
                            .map(c -> c.before)
                            .toList();
            try {
                if (!before.isEmpty()) {
                    this.consumersIndex.setConsumers(before);
                }
            } catch (Exception e) {
                log.error(
                        Constants.E_LOG_SWAP_ROLLBACK_FAILED,
                        candidates.stream().map(Candidate::type).toList(),
                        e.getMessage());
                return false;
            }
        }
        for (Candidate candidate : candidates) {
            boolean documentNamesNewSource =
                    documentsChanged && !candidate.rebuild && candidate.before == null;
            if (candidate.interrupted || documentNamesNewSource) {
                continue;
            }
            for (String alias : candidate.consumer.aliases()) {
                try {
                    this.deleteIndices(List.of(this.shadowPhysicalName(alias)));
                } catch (Exception e) {
                    log.warn(Constants.W_LOG_STAGING_INDEX_CLEANUP_FAILED, alias, e.getMessage());
                }
            }
        }
        return true;
    }

    /**
     * Deletes the indices left in the staging slot of a consumer that is not in the middle of a swap:
     * a staging index of a swap that failed and could not clean up, or a previous index a finished
     * swap could not delete.
     *
     * @param consumer The consumer.
     */
    private void deleteLeftovers(AbstractConsumerService consumer) {
        for (String alias : consumer.aliases()) {
            try {
                if (this.shadowIndexExists(alias)) {
                    String leftover = this.shadowPhysicalName(alias);
                    log.warn(Constants.W_LOG_STALE_SHADOW_INDEX_DELETED, leftover, alias);
                    this.deleteIndices(List.of(leftover));
                }
            } catch (Exception e) {
                log.warn(Constants.W_LOG_STAGING_INDEX_CLEANUP_FAILED, alias, e.getMessage());
            }
        }
    }

    /**
     * Returns whether any alias of the consumer has an index in its staging slot.
     *
     * @param consumer The consumer.
     * @return true if one of its staging slots holds an index.
     */
    private boolean anyShadowIndexExists(AbstractConsumerService consumer) {
        for (String alias : consumer.aliases()) {
            if (this.shadowIndexExists(alias)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns whether a consumer document is in the state a swap leaves it in until the switch:
     * {@code running} with nothing of its data source live yet.
     *
     * @param document The consumer document, or {@code null}.
     * @return true if the document is in that state.
     */
    static boolean isMidSwap(LocalConsumer document) {
        return document != null
                && document.getStatus() == LocalConsumer.Status.RUNNING
                && document.getLocalOffset() == 0;
    }

    private static List<String> types(List<Request> requests) {
        return requests.stream().map(r -> r.consumer.getConsumerType()).toList();
    }

    // Package-private so tests can replace the cluster operations.

    Map<String, ContentIndex> createStagingIndices(AbstractConsumerService consumer)
            throws Exception {
        return IndexSwapHelper.createShadowIndices(
                this.client, consumer.getMappings(), consumer::getIndexName);
    }

    String livePhysicalName(String alias) {
        return IndexSwapHelper.resolveLivePhysicalName(this.client, alias);
    }

    String shadowPhysicalName(String alias) {
        return IndexSwapHelper.resolveShadowName(this.client, alias);
    }

    boolean shadowIndexExists(String alias) {
        return IndexSwapHelper.shadowIndexExists(this.client, alias);
    }

    void copyUserContent(Map<String, String> liveToStaging) {
        IndexSwapHelper.reindexUserContent(
                this.client, liveToStaging, PluginSettings.getInstance().getClientTimeout());
    }

    void refreshIndices(Collection<String> indices) throws Exception {
        IndexSwapHelper.refreshIndices(
                this.client, indices, PluginSettings.getInstance().getClientTimeout());
    }

    void switchAliases(Map<String, String> aliasToStaging, Map<String, String> aliasToLive)
            throws Exception {
        IndexSwapHelper.atomicSwap(
                this.client, aliasToStaging, aliasToLive, PluginSettings.getInstance().getClientTimeout());
    }

    void deleteIndices(Collection<String> indices) {
        IndexSwapHelper.deleteIndices(this.client, indices);
    }

    /** What a swap did to the content of its consumers. */
    private enum SwapResult {
        /** The swap failed before the switch: the current content was kept. */
        KEPT,
        /**
         * The swap failed before the switch and the current content was kept, but the documents of the
         * moving consumers could not be restored and still name the new data sources.
         */
        KEPT_UNRESTORED,
        /** The new content is live and its offsets are recorded. */
        SWITCHED,
        /** The new content is live but its offsets could not be recorded. */
        SWITCHED_UNRECORDED
    }

    /**
     * A consumer that moves in a swap, as decided at the start of the pass.
     *
     * @param consumer The consumer.
     * @param target The data source it moves to.
     * @param document Its document before the swap, or {@code null} if it has none.
     * @param interrupted Whether the document is left over from an interrupted swap.
     */
    private record Request(
            AbstractConsumerService consumer,
            String target,
            LocalConsumer document,
            boolean interrupted) {}

    /** A consumer taking part in a swap, with everything needed to build its new content. */
    static final class Candidate {
        private final AbstractConsumerService consumer;
        private final String resource;
        private final RemoteConsumer remoteConsumer;
        private final ResourceUrlResolver urlResolver;
        private final TokenExchangeServiceImpl tokenExchangeService;

        /** Whether this is a rebuild from the data source the consumer is already on. */
        private boolean rebuild;

        /** The consumer document before the swap, restored if the swap fails. */
        private LocalConsumer before;

        /** Whether the document before the swap is left over from an interrupted swap. */
        private boolean interrupted;

        private Map<String, ContentIndex> staging = Map.of();
        private final Map<String, String> aliasToLive = new LinkedHashMap<>();
        private final Map<String, String> aliasToStaging = new LinkedHashMap<>();

        /**
         * Constructs a new Candidate.
         *
         * @param consumer The consumer.
         * @param resource The data source its new content comes from.
         * @param remoteConsumer The remote consumer of that data source.
         * @param urlResolver The URL resolver for the download.
         * @param tokenExchangeService The token exchange service behind the URL resolver, closed once
         *     the swap ends, or {@code null}.
         */
        Candidate(
                AbstractConsumerService consumer,
                String resource,
                RemoteConsumer remoteConsumer,
                ResourceUrlResolver urlResolver,
                TokenExchangeServiceImpl tokenExchangeService) {
            this.consumer = consumer;
            this.resource = resource;
            this.remoteConsumer = remoteConsumer;
            this.urlResolver = urlResolver;
            this.tokenExchangeService = tokenExchangeService;
        }

        private String type() {
            return this.consumer.getConsumerType();
        }

        /**
         * Returns the consumer document on the new data source, {@code running} and with the given
         * local offset. It keeps the phases pending before the swap and adds the ones the new content
         * leaves owed, so a pass cut after the switch still runs them.
         *
         * @param localOffset How much of the new content is live.
         * @return the document.
         */
        private LocalConsumer document(long localOffset) {
            return new LocalConsumer(
                    PluginSettings.getContextFromCatalogUri(this.resource),
                    PluginSettings.getConsumerFromCatalogUri(this.resource),
                    this.type(),
                    this.resource,
                    this.remoteConsumer.isPublic(),
                    LocalConsumer.Status.RUNNING,
                    localOffset,
                    this.remoteConsumer.getOffset(),
                    AbstractConsumerService.mergePhases(
                            this.before != null ? this.before.getPendingSyncPhases() : null,
                            this.consumer.phasesOwedByContentChange()));
        }

        private void close() {
            if (this.tokenExchangeService != null) {
                this.tokenExchangeService.close();
            }
        }
    }
}
