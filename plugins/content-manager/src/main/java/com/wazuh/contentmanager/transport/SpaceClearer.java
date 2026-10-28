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
package com.wazuh.contentmanager.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Orchestrates the scoped space clears: wiping only the normalization resources (decoders, kvdbs,
 * filters and the policy root decoder) or only the detection resources (rules) of a space, instead
 * of the whole space.
 *
 * <p>Lives in the transport package because the reconciliation rewrites the space policy through
 * the package-private {@link PolicyLinks}, the single guarded writer of the policy document.
 *
 * <p>Unlike the full reset ({@code TransportDeleteSpaceAction} with {@code FULL} scope), which
 * deletes the policy document and re-seeds a default one, the scoped clears only remove resources
 * and the policy's references to them (root decoder, integration and filter references). The
 * policy's own settings ({@code enrichments}, {@code enabled}, the {@code index_*} flags and the
 * metadata) are intentionally PRESERVED, as issue #1722 specifies per endpoint ("unset the root
 * decoder" only). Do not add a policy re-seed here: that would turn a one-sided clear into a reset
 * of unrelated space settings.
 */
final class SpaceClearer {

    private static final Logger log = LogManager.getLogger(SpaceClearer.class);

    /**
     * Bounded retry for the Security Analytics log-type delete when it transiently reports that the
     * integration still has active rules just after those rules were deleted.
     */
    private static final int LOG_TYPE_DELETE_MAX_ATTEMPTS = 5;

    private static final long LOG_TYPE_DELETE_BACKOFF_MILLIS = 300;

    private SpaceClearer() {}

    /**
     * Clears the normalization side of a space: deletes its decoders, kvdbs and filters, blanks the
     * policy root decoder, drops the policy's filter references, removes any integration left empty,
     * and recomputes the space hash. The detection side (rules) is left untouched.
     *
     * <p>Best-effort and re-runnable: there is no multi-document transaction, and a failed run can be
     * repeated. Failures are propagated to {@code listener}, never swallowed.
     *
     * @param client OpenSearch client.
     * @param spaceService bulk resource deletes and the space hash recompute.
     * @param integrationService integration document reads and writes.
     * @param securityAnalyticsService external (SAP) cleanup.
     * @param spaceName the space to clear (only {@code draft} is reachable through the REST layer).
     * @param listener notified once the normalization side has been cleared.
     */
    static void clearNormalization(
            Client client,
            SpaceService spaceService,
            IntegrationService integrationService,
            SecurityAnalyticsService securityAnalyticsService,
            String spaceName,
            ActionListener<Void> listener) {
        Space space = Space.fromValue(spaceName);
        // Set by any step that changed something; a no-op clear then skips the hash recompute (#1722).
        AtomicBoolean touched = new AtomicBoolean(false);
        // 1. Delete the normalization resources: decoders, kvdbs and filters.
        spaceService.deleteSpaceResources(
                space,
                List.of(Constants.INDEX_DECODERS, Constants.INDEX_KVDBS, Constants.INDEX_FILTERS),
                ActionListener.wrap(
                        resourcesDeleted -> {
                            if (resourcesDeleted) {
                                touched.set(true);
                            }
                            // 2. Blank the policy root decoder.
                            PolicyLinks.clearRootDecoder(
                                    client,
                                    spaceName,
                                    Constants.E_500_MISSING_DRAFT_POLICY,
                                    ActionListener.wrap(
                                            rootCleared -> {
                                                if (rootCleared) {
                                                    touched.set(true);
                                                }
                                                // 3. Drop the policy's filter references.
                                                PolicyLinks.clearList(
                                                        client,
                                                        spaceName,
                                                        Constants.KEY_FILTERS,
                                                        Constants.E_500_MISSING_DRAFT_POLICY,
                                                        ActionListener.wrap(
                                                                filtersCleared -> {
                                                                    if (filtersCleared) {
                                                                        touched.set(true);
                                                                    }
                                                                    // 4. Remove integrations left empty.
                                                                    reconcileEmptyIntegrations(
                                                                            client,
                                                                            integrationService,
                                                                            securityAnalyticsService,
                                                                            spaceName,
                                                                            Set.of(Constants.KEY_DECODERS, Constants.KEY_KVDBS),
                                                                            ActionListener.wrap(
                                                                                    reconciled -> {
                                                                                        if (reconciled) {
                                                                                            touched.set(true);
                                                                                        }
                                                                                        // 5. Recompute the hash, unless nothing changed.
                                                                                        recomputeHashIfChanged(
                                                                                                spaceService, spaceName, touched.get(), listener);
                                                                                    },
                                                                                    listener::onFailure));
                                                                },
                                                                listener::onFailure));
                                            },
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    /**
     * Recomputes the space's aggregate hash after a scoped clear, unless the clear changed nothing. A
     * no-op clear must leave the hash unchanged (issue #1722); a fresh reset stores the policy's own
     * hash, which a recompute to the aggregate hash would otherwise move.
     */
    private static void recomputeHashIfChanged(
            SpaceService spaceService, String spaceName, boolean changed, ActionListener<Void> listener) {
        if (changed == false) {
            listener.onResponse(null);
            return;
        }
        spaceService.calculateAndUpdate(
                List.of(spaceName),
                ActionListener.wrap(updated -> listener.onResponse(null), listener::onFailure));
    }

    /**
     * Clears the detection side of a space: removes its rules from Security Analytics and from the
     * index, removes any integration left empty, and recomputes the space hash. The normalization
     * side (decoders, kvdbs, filters and the root decoder) is left untouched.
     *
     * <p>Best-effort and re-runnable; failures are propagated to {@code listener}, never swallowed.
     * The rule documents are deleted last, after Security Analytics has been cleaned, so a run that
     * fails midway leaves the rules in the index for the next run to re-find and finish.
     *
     * @param client OpenSearch client.
     * @param spaceService rule-id listing, bulk resource deletes and the space hash recompute.
     * @param integrationService integration document reads and writes.
     * @param securityAnalyticsService external (SAP) cleanup.
     * @param spaceName the space to clear (only {@code draft} is reachable through the REST layer).
     * @param listener notified once the detection side has been cleared.
     */
    static void clearDetection(
            Client client,
            SpaceService spaceService,
            IntegrationService integrationService,
            SecurityAnalyticsService securityAnalyticsService,
            String spaceName,
            ActionListener<Void> listener) {
        Space space = Space.fromValue(spaceName);
        // Set by any step that changed something; a no-op clear then skips the hash recompute (#1722).
        AtomicBoolean touched = new AtomicBoolean(false);
        // 1. Mirror the single-rule delete's external cleanup for every rule in the space.
        spaceService.getSpaceResourceIdsAsync(
                spaceName,
                List.of(Constants.KEY_RULES),
                ActionListener.wrap(
                        idsByType -> {
                            List<String> ruleIds = idsByType.getOrDefault(Constants.KEY_RULES, List.of());
                            deleteRulesInSecurityAnalytics(
                                    securityAnalyticsService,
                                    ruleIds,
                                    ActionListener.wrap(
                                            saDone ->
                                                    // 2. Remove integrations left empty (and their Security
                                                    // Analytics log types).
                                                    reconcileEmptyIntegrations(
                                                            client,
                                                            integrationService,
                                                            securityAnalyticsService,
                                                            spaceName,
                                                            Set.of(Constants.KEY_RULES),
                                                            ActionListener.wrap(
                                                                    reconciled -> {
                                                                        if (reconciled) {
                                                                            touched.set(true);
                                                                        }
                                                                        // 3. Delete the rule documents LAST: they are the
                                                                        // source getSpaceResourceIdsAsync reads, so a failed
                                                                        // run leaves them for the next run to re-find.
                                                                        spaceService.deleteSpaceResources(
                                                                                space,
                                                                                List.of(Constants.INDEX_RULES),
                                                                                ActionListener.wrap(
                                                                                        rulesDeleted -> {
                                                                                            if (rulesDeleted) {
                                                                                                touched.set(true);
                                                                                            }
                                                                                            // 4. Recompute the hash, unless nothing changed.
                                                                                            recomputeHashIfChanged(
                                                                                                    spaceService, spaceName, touched.get(), listener);
                                                                                        },
                                                                                        listener::onFailure));
                                                                    },
                                                                    listener::onFailure)),
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    /** Removes each rule from Security Analytics, as the single-rule delete does. */
    private static void deleteRulesInSecurityAnalytics(
            SecurityAnalyticsService securityAnalyticsService,
            List<String> ruleIds,
            ActionListener<Void> listener) {
        if (ruleIds.isEmpty()) {
            listener.onResponse(null);
            return;
        }
        GroupedActionListener<Void> group =
                new GroupedActionListener<>(
                        ActionListener.wrap(ignored -> listener.onResponse(null), listener::onFailure),
                        ruleIds.size());
        for (String ruleId : ruleIds) {
            securityAnalyticsService.deleteRule(
                    ruleId,
                    Space.DRAFT,
                    ActionListener.wrap(
                            response -> group.onResponse(null),
                            e -> {
                                // A rule already gone from Security Analytics is fine; tolerate it so a
                                // re-run after a partial failure converges, as the single-rule delete does.
                                if (isNotFoundException(e)) {
                                    group.onResponse(null);
                                } else {
                                    group.onFailure(e);
                                }
                            }));
        }
    }

    /**
     * After a side of the space has been cleared, removes every integration left with no decoders,
     * rules or kvdbs.
     *
     * <p>In one pass over the space's integrations: empties the {@code clearedFields} lists on each
     * (they point at resources that no longer exist) and, for every non-protected integration left
     * empty, deletes the integration document, unlinks it from the policy, and removes it from
     * Security Analytics. Protected integrations keep their place even when left empty.
     *
     * @param client OpenSearch client.
     * @param integrationService integration document reads and writes.
     * @param securityAnalyticsService external (SAP) cleanup.
     * @param spaceName the space being cleared.
     * @param clearedFields the integration list fields emptied by this clear ({@code decoders} +
     *     {@code kvdbs} for normalization, {@code rules} for detection).
     * @param listener receives whether any integration was actually changed (a field emptied or the
     *     integration removed), or a failure.
     */
    static void reconcileEmptyIntegrations(
            Client client,
            IntegrationService integrationService,
            SecurityAnalyticsService securityAnalyticsService,
            String spaceName,
            Set<String> clearedFields,
            ActionListener<Boolean> listener) {
        integrationService.listIntegrationIdsAsync(
                spaceName,
                ActionListener.wrap(
                        integrationIds -> {
                            if (integrationIds.isEmpty()) {
                                listener.onResponse(false);
                                return;
                            }
                            AtomicBoolean changed = new AtomicBoolean(false);
                            GroupedActionListener<Void> group =
                                    new GroupedActionListener<>(
                                            ActionListener.wrap(
                                                    ignored -> listener.onResponse(changed.get()), listener::onFailure),
                                            integrationIds.size());
                            for (String id : integrationIds) {
                                integrationService.emptyFieldsAsync(
                                        id,
                                        clearedFields,
                                        ActionListener.wrap(
                                                result -> {
                                                    if (result.changed()) {
                                                        changed.set(true);
                                                    }
                                                    if (result.nowEmpty() && result.isProtected() == false) {
                                                        changed.set(true);
                                                        deleteEmptyIntegration(
                                                                client,
                                                                integrationService,
                                                                securityAnalyticsService,
                                                                spaceName,
                                                                id,
                                                                group);
                                                    } else {
                                                        group.onResponse(null);
                                                    }
                                                },
                                                group::onFailure));
                            }
                        },
                        listener::onFailure));
    }

    /**
     * Deletes an empty integration everywhere it is referenced: index, policy and Security Analytics.
     */
    private static void deleteEmptyIntegration(
            Client client,
            IntegrationService integrationService,
            SecurityAnalyticsService securityAnalyticsService,
            String spaceName,
            String id,
            ActionListener<Void> listener) {
        deleteEmptyIntegration(
                client, integrationService, securityAnalyticsService, spaceName, id, 1, listener);
    }

    private static void deleteEmptyIntegration(
            Client client,
            IntegrationService integrationService,
            SecurityAnalyticsService securityAnalyticsService,
            String spaceName,
            String id,
            int attempt,
            ActionListener<Void> listener) {
        // Mirror the single-integration delete order so a partial failure converges on re-run:
        // remove from Security Analytics (tolerating a 404), then unlink from the policy, and only
        // then delete the integration document. The document is deleted last because it is what lets
        // a re-run re-find and finish reconciling the integration.
        securityAnalyticsService.deleteIntegration(
                id,
                Space.DRAFT,
                ActionListener.wrap(
                        response ->
                                unlinkThenDeleteDocument(client, integrationService, spaceName, id, listener),
                        e -> {
                            if (isNotFoundException(e)) {
                                unlinkThenDeleteDocument(client, integrationService, spaceName, id, listener);
                            } else if (isActiveRulesConflict(e) && attempt < LOG_TYPE_DELETE_MAX_ATTEMPTS) {
                                // Security Analytics is eventually consistent after the rule delete and may
                                // still report active rules; back off and retry so a single clear/detection
                                // converges instead of erroring.
                                log.debug(
                                        "Security Analytics still reports active rules for integration [{}];"
                                                + " retrying its log-type delete (attempt {}/{}).",
                                        id,
                                        attempt + 1,
                                        LOG_TYPE_DELETE_MAX_ATTEMPTS);
                                client
                                        .threadPool()
                                        .schedule(
                                                () ->
                                                        deleteEmptyIntegration(
                                                                client,
                                                                integrationService,
                                                                securityAnalyticsService,
                                                                spaceName,
                                                                id,
                                                                attempt + 1,
                                                                listener),
                                                TimeValue.timeValueMillis(LOG_TYPE_DELETE_BACKOFF_MILLIS),
                                                ThreadPool.Names.GENERIC);
                            } else {
                                listener.onFailure(e);
                            }
                        }));
    }

    /**
     * Whether {@code e} (or a cause) is Security Analytics refusing the log-type delete with a {@code
     * 400}. Detected by status, not by message text: when clearing an empty draft integration the
     * only {@code 400} the delete can raise is that it still sees the rules just deleted (a transient
     * after the rule delete — draft integrations have no detectors and no sigma source), which is the
     * one case worth retrying. A {@code 404} is tolerated earlier; anything else propagates.
     */
    private static boolean isActiveRulesConflict(Exception e) {
        Throwable cause = e;
        while (cause != null) {
            if (cause instanceof OpenSearchStatusException statusException
                    && statusException.status() == RestStatus.BAD_REQUEST) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private static void unlinkThenDeleteDocument(
            Client client,
            IntegrationService integrationService,
            String spaceName,
            String id,
            ActionListener<Void> listener) {
        PolicyLinks.unlink(
                client,
                spaceName,
                Constants.KEY_INTEGRATIONS,
                id,
                Constants.E_500_MISSING_DRAFT_POLICY,
                ActionListener.wrap(
                        unlinked -> integrationService.deleteIntegrationDocAsync(id, listener),
                        listener::onFailure));
    }

    /**
     * Whether {@code e} or one of its causes is an OpenSearch 404, as the single-delete path checks.
     */
    private static boolean isNotFoundException(Exception e) {
        Throwable cause = e;
        while (cause != null) {
            if (cause instanceof OpenSearchStatusException statusException
                    && statusException.status() == RestStatus.NOT_FOUND) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }
}
