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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.ValueInstantiationException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.rest.RestRequest;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.PostPromoteAction;
import com.wazuh.contentmanager.action.PostPromoteRequest;
import com.wazuh.contentmanager.action.ReloadEngineContentAction;
import com.wazuh.contentmanager.action.ReloadEngineContentRequest;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.DetectorLookupService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.cti.catalog.utils.DetectorRuleGuard;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.model.SpaceDiff;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport action for POST /promote. Executes the full promotion process: validation, engine
 * check, consolidation to target space with rollback support.
 */
public class TransportPostPromoteAction
        extends HandledTransportAction<PostPromoteRequest, MessageStatusResponse> {

    private static final Logger log = LogManager.getLogger(TransportPostPromoteAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** All resource types in the order they should be processed during consolidation. */
    private static final List<String> APPLY_RESOURCE_TYPES =
            List.of(
                    Constants.KEY_POLICY,
                    Constants.KEY_INTEGRATIONS,
                    Constants.KEY_KVDBS,
                    Constants.KEY_DECODERS,
                    Constants.KEY_FILTERS,
                    Constants.KEY_RULES);

    /** Resource types that support DELETE operations (policy cannot be deleted). */
    private static final List<String> DELETE_RESOURCE_TYPES =
            List.of(
                    Constants.KEY_INTEGRATIONS,
                    Constants.KEY_KVDBS,
                    Constants.KEY_DECODERS,
                    Constants.KEY_FILTERS,
                    Constants.KEY_RULES);

    private final SpaceService spaceService;
    private final EngineService engine;
    private final SecurityAnalyticsService securityAnalyticsService;
    private final Client client;
    private final DetectorLookupService detectorLookupService;

    @Inject
    public TransportPostPromoteAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SpaceService spaceService,
            EngineService engine,
            SecurityAnalyticsService securityAnalyticsService,
            Client client) {
        super(PostPromoteAction.NAME, transportService, actionFilters, PostPromoteRequest::new);
        this.spaceService = spaceService;
        this.engine = engine;
        this.securityAnalyticsService = securityAnalyticsService;
        this.client = client;
        this.detectorLookupService = new DetectorLookupService(client);
    }

    // ── Entry point ──────────────────────────────────────────────────────────

    @Override
    protected void doExecute(
            Task task, PostPromoteRequest request, ActionListener<MessageStatusResponse> listener) {
        if (this.engine == null) {
            log.error(Constants.E_LOG_ENGINE_IS_NULL);
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
            return;
        }

        String body = request.getBody();
        if (body == null || body.isBlank()) {
            listener.onResponse(
                    new MessageStatusResponse(Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
            return;
        }

        try {
            SpaceDiff spaceDiff = MAPPER.readValue(body, SpaceDiff.class);
            this.validatePromoteRequest(spaceDiff);

            this.validateNoDetectorLeftEmptyAsync(
                    spaceDiff,
                    ActionListener.wrap(
                            rejection -> {
                                if (rejection != null) {
                                    log.warn(Constants.W_LOG_VALIDATION_FAILED, rejection);
                                    listener.onResponse(new MessageStatusResponse(rejection, RestStatus.BAD_REQUEST));
                                    return;
                                }
                                this.gatherPromotionDataAsync(spaceDiff, listener);
                            },
                            e -> respondWithError(listener, e)));
        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            listener.onResponse(new MessageStatusResponse(e.getMessage(), RestStatus.BAD_REQUEST));
        } catch (ValueInstantiationException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
            listener.onResponse(new MessageStatusResponse(message, RestStatus.BAD_REQUEST));
        } catch (IOException e) {
            respondWithError(listener, e);
        }
    }

    // ── Gathering phase ──────────────────────────────────────────────────────

    private void gatherPromotionDataAsync(
            SpaceDiff spaceDiff, ActionListener<MessageStatusResponse> listener) {
        Space sourceSpace = spaceDiff.getSpace();
        Space targetSpace = sourceSpace.promote();
        SpaceDiff.Changes changes = spaceDiff.getChanges();

        this.spaceService.getPolicy(
                sourceSpace.toString(),
                ActionListener.wrap(
                        (Map<String, Object> policyDocument) -> {
                            if (policyDocument == null) {
                                respondWithError(
                                        listener,
                                        new IOException("Policy document not found for source space: " + sourceSpace));
                                return;
                            }

                            Map<String, Map<String, Object>> policyToApply = new HashMap<>();
                            Map<String, Map<String, Object>> integrationsToApply = new HashMap<>();
                            Map<String, Map<String, Object>> kvdbsToApply = new HashMap<>();
                            Map<String, Map<String, Object>> decodersToApply = new HashMap<>();
                            Map<String, Map<String, Object>> filtersToApply = new HashMap<>();
                            Map<String, Map<String, Object>> rulesToApply = new HashMap<>();

                            Set<String> integrationsToDelete = new HashSet<>();
                            Set<String> kvdbsToDelete = new HashSet<>();
                            Set<String> decodersToDelete = new HashSet<>();
                            Set<String> filtersToDelete = new HashSet<>();
                            Set<String> rulesToDelete = new HashSet<>();

                            List<ResourceChangeEntry> entries =
                                    List.of(
                                            new ResourceChangeEntry(
                                                    changes.getPolicy(),
                                                    Constants.KEY_POLICY,
                                                    policyToApply,
                                                    HashSet.newHashSet(0)),
                                            new ResourceChangeEntry(
                                                    changes.getIntegrations(),
                                                    Constants.KEY_INTEGRATIONS,
                                                    integrationsToApply,
                                                    integrationsToDelete),
                                            new ResourceChangeEntry(
                                                    changes.getKvdbs(), Constants.KEY_KVDBS, kvdbsToApply, kvdbsToDelete),
                                            new ResourceChangeEntry(
                                                    changes.getDecoders(),
                                                    Constants.KEY_DECODERS,
                                                    decodersToApply,
                                                    decodersToDelete),
                                            new ResourceChangeEntry(
                                                    changes.getFilters(),
                                                    Constants.KEY_FILTERS,
                                                    filtersToApply,
                                                    filtersToDelete),
                                            new ResourceChangeEntry(
                                                    changes.getRules(), Constants.KEY_RULES, rulesToApply, rulesToDelete));

                            processAllResourceTypesAsync(
                                    entries,
                                    0,
                                    sourceSpace.toString(),
                                    targetSpace.toString(),
                                    ActionListener.wrap(
                                            v ->
                                                    buildPayloadAndCapture(
                                                            policyDocument,
                                                            targetSpace,
                                                            policyToApply,
                                                            integrationsToApply,
                                                            kvdbsToApply,
                                                            decodersToApply,
                                                            filtersToApply,
                                                            rulesToApply,
                                                            integrationsToDelete,
                                                            kvdbsToDelete,
                                                            decodersToDelete,
                                                            filtersToDelete,
                                                            rulesToDelete,
                                                            spaceDiff,
                                                            listener),
                                            e -> respondWithError(listener, e)));
                        },
                        e -> respondWithError(listener, e)));
    }

    private void buildPayloadAndCapture(
            Map<String, Object> policyDocument,
            Space targetSpace,
            Map<String, Map<String, Object>> policyToApply,
            Map<String, Map<String, Object>> integrationsToApply,
            Map<String, Map<String, Object>> kvdbsToApply,
            Map<String, Map<String, Object>> decodersToApply,
            Map<String, Map<String, Object>> filtersToApply,
            Map<String, Map<String, Object>> rulesToApply,
            Set<String> integrationsToDelete,
            Set<String> kvdbsToDelete,
            Set<String> decodersToDelete,
            Set<String> filtersToDelete,
            Set<String> rulesToDelete,
            SpaceDiff spaceDiff,
            ActionListener<MessageStatusResponse> listener) {
        this.spaceService.buildEnginePayload(
                policyDocument,
                targetSpace.toString(),
                integrationsToApply,
                kvdbsToApply,
                decodersToApply,
                filtersToApply,
                integrationsToDelete,
                kvdbsToDelete,
                decodersToDelete,
                filtersToDelete,
                ActionListener.wrap(
                        (JsonNode enginePayload) -> {
                            PromotionContext context =
                                    new PromotionContext(
                                            enginePayload,
                                            policyToApply,
                                            integrationsToApply,
                                            kvdbsToApply,
                                            decodersToApply,
                                            filtersToApply,
                                            rulesToApply,
                                            integrationsToDelete,
                                            kvdbsToDelete,
                                            decodersToDelete,
                                            filtersToDelete,
                                            rulesToDelete,
                                            targetSpace.toString());

                            captureAllOldVersionsAsync(
                                    context,
                                    APPLY_RESOURCE_TYPES,
                                    0,
                                    ActionListener.wrap(
                                            v ->
                                                    captureAllDeleteSnapshotsAsync(
                                                            context,
                                                            DELETE_RESOURCE_TYPES,
                                                            0,
                                                            ActionListener.wrap(
                                                                    v2 -> afterGatheringPhase(context, spaceDiff, listener),
                                                                    e -> respondWithError(listener, e))),
                                            e -> respondWithError(listener, e)));
                        },
                        e -> respondWithError(listener, e)));
    }

    // ── Process resource changes ─────────────────────────────────────────────

    private void processAllResourceTypesAsync(
            List<ResourceChangeEntry> entries,
            int idx,
            String sourceSpace,
            String targetSpace,
            ActionListener<Void> listener) {
        if (idx >= entries.size()) {
            listener.onResponse(null);
            return;
        }
        ResourceChangeEntry entry = entries.get(idx);
        String indexName = this.spaceService.getIndexForResourceType(entry.resourceType);
        if (indexName == null) {
            listener.onFailure(
                    new IllegalArgumentException("Unknown resource type: " + entry.resourceType));
            return;
        }
        processResourceChangesAsync(
                entry.items,
                0,
                entry.resourceType,
                indexName,
                entry.resourcesToApply,
                entry.resourcesToDelete,
                sourceSpace,
                targetSpace,
                ActionListener.wrap(
                        v -> processAllResourceTypesAsync(entries, idx + 1, sourceSpace, targetSpace, listener),
                        listener::onFailure));
    }

    private void processResourceChangesAsync(
            List<SpaceDiff.OperationItem> items,
            int idx,
            String resourceType,
            String indexName,
            Map<String, Map<String, Object>> resourcesToApply,
            Set<String> resourcesToDelete,
            String sourceSpace,
            String targetSpace,
            ActionListener<Void> listener) {
        if (idx >= items.size()) {
            listener.onResponse(null);
            return;
        }
        SpaceDiff.OperationItem item = items.get(idx);
        String resourceId = item.getId();

        ActionListener<Void> next =
                ActionListener.wrap(
                        v ->
                                processResourceChangesAsync(
                                        items,
                                        idx + 1,
                                        resourceType,
                                        indexName,
                                        resourcesToApply,
                                        resourcesToDelete,
                                        sourceSpace,
                                        targetSpace,
                                        listener),
                        listener::onFailure);

        switch (item.getOperation()) {
            case ADD ->
                    processAddAsync(
                            resourceId,
                            indexName,
                            resourceType,
                            resourcesToApply,
                            sourceSpace,
                            targetSpace,
                            next);
            case UPDATE ->
                    processUpdateAsync(
                            resourceId, resourceType, indexName, resourcesToApply, sourceSpace, next);
            case REMOVE ->
                    processRemoveAsync(resourceId, indexName, resourcesToDelete, targetSpace, next);
        }
    }

    private void processAddAsync(
            String resourceId,
            String indexName,
            String resourceType,
            Map<String, Map<String, Object>> resourcesToApply,
            String sourceSpace,
            String targetSpace,
            ActionListener<Void> listener) {
        this.spaceService.getDocumentAsync(
                indexName,
                sourceSpace,
                resourceId,
                ActionListener.wrap(
                        (Map<String, Object> sourceDoc) -> {
                            if (sourceDoc == null) {
                                listener.onFailure(
                                        new IOException(
                                                "Resource '"
                                                        + resourceId
                                                        + "' not found in "
                                                        + resourceType
                                                        + " for ADD operation"));
                                return;
                            }
                            validateSourceSpace(sourceDoc, resourceId, sourceSpace);

                            this.spaceService.getDocumentAsync(
                                    indexName,
                                    targetSpace,
                                    resourceId,
                                    ActionListener.wrap(
                                            (Map<String, Object> targetDoc) -> {
                                                if (targetDoc != null) {
                                                    @SuppressWarnings("unchecked")
                                                    Map<String, String> targetDocSpace =
                                                            (Map<String, String>)
                                                                    targetDoc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                                                    String targetDocSpaceName = targetDocSpace.get(Constants.KEY_NAME);
                                                    if (targetSpace.equals(targetDocSpaceName)) {
                                                        listener.onFailure(
                                                                new OpenSearchStatusException(
                                                                        "Resource '"
                                                                                + resourceId
                                                                                + "' already exists in target space '"
                                                                                + targetSpace
                                                                                + "', use UPDATE operation instead",
                                                                        RestStatus.CONFLICT));
                                                        return;
                                                    }
                                                }
                                                resourcesToApply.put(resourceId, sourceDoc);
                                                listener.onResponse(null);
                                            },
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    private void processUpdateAsync(
            String resourceId,
            String resourceType,
            String indexName,
            Map<String, Map<String, Object>> resourcesToApply,
            String sourceSpace,
            ActionListener<Void> listener) {
        ActionListener<Map<String, Object>> docListener =
                ActionListener.wrap(
                        (Map<String, Object> sourceDoc) -> {
                            if (sourceDoc == null) {
                                listener.onFailure(
                                        new IOException(
                                                "Resource '"
                                                        + resourceId
                                                        + "' not found in "
                                                        + resourceType
                                                        + " for UPDATE operation"));
                                return;
                            }
                            validateSourceSpace(sourceDoc, resourceId, sourceSpace);
                            resourcesToApply.put(resourceId, sourceDoc);
                            listener.onResponse(null);
                        },
                        listener::onFailure);

        if (resourceType.equals(Constants.KEY_POLICY)) {
            this.spaceService.getPolicy(sourceSpace, docListener);
        } else {
            this.spaceService.getDocumentAsync(indexName, sourceSpace, resourceId, docListener);
        }
    }

    private void processRemoveAsync(
            String resourceId,
            String indexName,
            Set<String> resourcesToDelete,
            String targetSpace,
            ActionListener<Void> listener) {
        this.spaceService.getDocumentAsync(
                indexName,
                targetSpace,
                resourceId,
                ActionListener.wrap(
                        (Map<String, Object> targetDoc) -> {
                            if (targetDoc != null) {
                                @SuppressWarnings("unchecked")
                                Map<String, String> targetDocSpace =
                                        (Map<String, String>)
                                                targetDoc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                                String targetDocSpaceName = targetDocSpace.get(Constants.KEY_NAME);
                                if (!targetSpace.equals(targetDocSpaceName)) {
                                    log.warn(
                                            Constants.W_LOG_RESOURCE_NOT_IN_TARGET_SPACE,
                                            resourceId,
                                            targetDocSpaceName,
                                            targetSpace);
                                }
                            }
                            resourcesToDelete.add(resourceId);
                            log.debug(Constants.D_LOG_RESOURCE_MARKED_FOR_DELETION, resourceId, targetSpace);
                            listener.onResponse(null);
                        },
                        listener::onFailure));
    }

    @SuppressWarnings("unchecked")
    private static void validateSourceSpace(
            Map<String, Object> sourceDoc, String resourceId, String sourceSpace) {
        Map<String, String> sourceDocSpace =
                (Map<String, String>) sourceDoc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
        String docSpace = sourceDocSpace.get(Constants.KEY_NAME);
        if (!sourceSpace.equals(docSpace)) {
            throw new IllegalArgumentException(
                    "Resource '"
                            + resourceId
                            + "' is in space '"
                            + docSpace
                            + "', expected source space '"
                            + sourceSpace
                            + "'");
        }
    }

    // ── Capture old versions / delete snapshots ──────────────────────────────

    private void captureAllOldVersionsAsync(
            PromotionContext context, List<String> types, int typeIdx, ActionListener<Void> listener) {
        if (typeIdx >= types.size()) {
            listener.onResponse(null);
            return;
        }
        String resourceType = types.get(typeIdx);
        Map<String, Map<String, Object>> resourcesToApply = context.getApplyMap(resourceType);
        if (resourcesToApply.isEmpty()) {
            captureAllOldVersionsAsync(context, types, typeIdx + 1, listener);
            return;
        }
        String indexName = this.spaceService.getIndexForResourceType(resourceType);
        Map<String, Map<String, Object>> dest =
                context.oldVersions.computeIfAbsent(resourceType, k -> new HashMap<>());
        List<String> docIds = new ArrayList<>(resourcesToApply.keySet());

        captureOldVersionsForTypeAsync(
                context,
                resourceType,
                indexName,
                docIds,
                0,
                dest,
                ActionListener.wrap(
                        v -> captureAllOldVersionsAsync(context, types, typeIdx + 1, listener),
                        listener::onFailure));
    }

    private void captureOldVersionsForTypeAsync(
            PromotionContext context,
            String resourceType,
            String indexName,
            List<String> docIds,
            int idx,
            Map<String, Map<String, Object>> dest,
            ActionListener<Void> listener) {
        if (idx >= docIds.size()) {
            listener.onResponse(null);
            return;
        }
        String docId = docIds.get(idx);
        ActionListener<Map<String, Object>> docListener =
                ActionListener.wrap(
                        (Map<String, Object> existing) -> {
                            dest.put(docId, existing);
                            captureOldVersionsForTypeAsync(
                                    context, resourceType, indexName, docIds, idx + 1, dest, listener);
                        },
                        e -> {
                            log.warn(
                                    Constants.W_LOG_SNAPSHOT_OLD_VERSION_FAILED, docId, resourceType, e.getMessage());
                            listener.onFailure(e);
                        });

        if (resourceType.equals(Constants.KEY_POLICY)) {
            this.spaceService.getPolicy(context.targetSpace, docListener);
        } else {
            this.spaceService.getDocumentAsync(indexName, context.targetSpace, docId, docListener);
        }
    }

    private void captureAllDeleteSnapshotsAsync(
            PromotionContext context, List<String> types, int typeIdx, ActionListener<Void> listener) {
        if (typeIdx >= types.size()) {
            listener.onResponse(null);
            return;
        }
        String resourceType = types.get(typeIdx);
        Set<String> idsToDelete = context.getDeleteSet(resourceType);
        if (idsToDelete.isEmpty()) {
            captureAllDeleteSnapshotsAsync(context, types, typeIdx + 1, listener);
            return;
        }
        String indexName = this.spaceService.getIndexForResourceType(resourceType);
        Map<String, Map<String, Object>> dest =
                context.deleteSnapshots.computeIfAbsent(resourceType, k -> new HashMap<>());
        List<String> docIds = new ArrayList<>(idsToDelete);

        captureDeleteSnapshotsForTypeAsync(
                context,
                resourceType,
                indexName,
                docIds,
                0,
                dest,
                ActionListener.wrap(
                        v -> captureAllDeleteSnapshotsAsync(context, types, typeIdx + 1, listener),
                        listener::onFailure));
    }

    private void captureDeleteSnapshotsForTypeAsync(
            PromotionContext context,
            String resourceType,
            String indexName,
            List<String> docIds,
            int idx,
            Map<String, Map<String, Object>> dest,
            ActionListener<Void> listener) {
        if (idx >= docIds.size()) {
            listener.onResponse(null);
            return;
        }
        String docId = docIds.get(idx);
        this.spaceService.getDocumentAsync(
                indexName,
                context.targetSpace,
                docId,
                ActionListener.wrap(
                        (Map<String, Object> existing) -> {
                            if (existing != null) {
                                dest.put(docId, existing);
                            }
                            captureDeleteSnapshotsForTypeAsync(
                                    context, resourceType, indexName, docIds, idx + 1, dest, listener);
                        },
                        e -> {
                            log.error(
                                    Constants.E_LOG_SNAPSHOT_DELETE_TARGET_FAILED,
                                    docId,
                                    resourceType,
                                    e.getMessage());
                            listener.onFailure(e);
                        }));
    }

    // ── After gathering: engine validation ───────────────────────────────────

    private void afterGatheringPhase(
            PromotionContext context,
            SpaceDiff spaceDiff,
            ActionListener<MessageStatusResponse> listener) {
        Space targetSpace = spaceDiff.getSpace().promote();

        if ((targetSpace == Space.TEST || targetSpace == Space.CUSTOM)
                && this.hasEngineRelatedChanges(context)) {
            invokeEngineAndConsolidate(context, targetSpace, listener);
            return;
        }

        if (targetSpace == Space.TEST || targetSpace == Space.CUSTOM) {
            this.spaceService.hasEngineResourcesAsync(
                    targetSpace,
                    ActionListener.wrap(
                            (Boolean hasResources) -> {
                                if (hasResources) {
                                    invokeEngineAndConsolidate(context, targetSpace, listener);
                                } else {
                                    consolidateChangesAsync(context, listener);
                                }
                            },
                            e -> respondWithError(listener, e)));
        } else {
            consolidateChangesAsync(context, listener);
        }
    }

    private void invokeEngineAndConsolidate(
            PromotionContext context, Space targetSpace, ActionListener<MessageStatusResponse> listener) {
        this.engine.promoteAsync(
                context.enginePayload,
                ActionListener.wrap(
                        engineResponse -> {
                            if (engineResponse.getStatus() != RestStatus.OK.getStatus()
                                    && engineResponse.getStatus() != RestStatus.ACCEPTED.getStatus()) {
                                RestResponse shaped =
                                        TransportActionHelper.fromDownstreamValidation(engineResponse);
                                if (shaped.getStatus() < 500) {
                                    log.warn(Constants.W_LOG_VALIDATION_FAILED, shaped.getMessage());
                                } else {
                                    log.error(Constants.W_LOG_VALIDATION_FAILED, shaped.getMessage());
                                }
                                try {
                                    log.debug(
                                            Constants.D_LOG_ENGINE_REJECTED_PAYLOAD,
                                            MAPPER.writeValueAsString(context.enginePayload));
                                } catch (IOException ignored) {
                                }
                                listener.onResponse(
                                        new MessageStatusResponse(
                                                shaped.getMessage(), RestStatus.fromCode(shaped.getStatus())));
                                return;
                            }
                            log.debug(Constants.D_LOG_ENGINE_VALIDATION_COMPLETE, targetSpace);
                            consolidateChangesAsync(context, listener);
                        },
                        listener::onFailure));
    }

    // ── Consolidation phase ──────────────────────────────────────────────────

    private void consolidateChangesAsync(
            PromotionContext context, ActionListener<MessageStatusResponse> listener) {
        applyResourceTypesAsync(
                context,
                APPLY_RESOURCE_TYPES,
                0,
                ActionListener.wrap(
                        v ->
                                deleteResourceTypesAsync(
                                        context,
                                        DELETE_RESOURCE_TYPES,
                                        0,
                                        ActionListener.wrap(
                                                v2 ->
                                                        sapSyncAsync(
                                                                context,
                                                                ActionListener.wrap(
                                                                        v3 -> afterConsolidationPhase(context, listener),
                                                                        e -> {
                                                                            log.warn(
                                                                                    "SAP sync error during consolidation: {}",
                                                                                    e.getMessage());
                                                                            afterConsolidationPhase(context, listener);
                                                                        })),
                                                e -> rollbackAndFail(context, e, listener))),
                        e -> rollbackAndFail(context, e, listener)));
    }

    private void applyResourceTypesAsync(
            PromotionContext context, List<String> types, int idx, ActionListener<Void> listener) {
        if (idx >= types.size()) {
            listener.onResponse(null);
            return;
        }
        String type = types.get(idx);
        Map<String, Map<String, Object>> resources = context.getApplyMap(type);
        if (resources.isEmpty()) {
            applyResourceTypesAsync(context, types, idx + 1, listener);
            return;
        }
        this.spaceService.promoteSpaceAsync(
                this.spaceService.getIndexForResourceType(type),
                resources,
                context.targetSpace,
                ActionListener.wrap(
                        v -> {
                            context.rollbackSteps.add(new RollbackStep(RollbackStep.Kind.APPLY, type));
                            applyResourceTypesAsync(context, types, idx + 1, listener);
                        },
                        listener::onFailure));
    }

    private void deleteResourceTypesAsync(
            PromotionContext context, List<String> types, int idx, ActionListener<Void> listener) {
        if (idx >= types.size()) {
            listener.onResponse(null);
            return;
        }
        String type = types.get(idx);
        Set<String> ids = context.getDeleteSet(type);
        if (ids.isEmpty()) {
            deleteResourceTypesAsync(context, types, idx + 1, listener);
            return;
        }
        this.spaceService.deleteResourcesAsync(
                this.spaceService.getIndexForResourceType(type),
                ids,
                context.targetSpace,
                ActionListener.wrap(
                        v -> {
                            context.rollbackSteps.add(new RollbackStep(RollbackStep.Kind.DELETE, type));
                            deleteResourceTypesAsync(context, types, idx + 1, listener);
                        },
                        listener::onFailure));
    }

    // ── SAP synchronization (best-effort) ────────────────────────────────────

    private void sapSyncAsync(PromotionContext context, ActionListener<Void> listener) {
        Space targetSpaceEnum = Space.fromValue(context.targetSpace);

        List<String> rulesToDelete = new ArrayList<>(context.rulesToDelete);
        List<String> integrationsToDelete = new ArrayList<>(context.integrationsToDelete);

        sapDeleteAsync(
                rulesToDelete,
                0,
                "rule",
                targetSpaceEnum,
                context.targetSpace,
                ActionListener.wrap(
                        v ->
                                sapDeleteAsync(
                                        integrationsToDelete,
                                        0,
                                        "integration",
                                        targetSpaceEnum,
                                        context.targetSpace,
                                        ActionListener.wrap(
                                                v2 ->
                                                        upsertSapResourcesAsync(
                                                                context.integrationsToApply,
                                                                context.oldVersions.getOrDefault(
                                                                        Constants.KEY_INTEGRATIONS, Collections.emptyMap()),
                                                                Constants.KEY_INTEGRATIONS,
                                                                targetSpaceEnum,
                                                                context.targetSpace,
                                                                ActionListener.wrap(
                                                                        v3 ->
                                                                                upsertSapResourcesAsync(
                                                                                        context.rulesToApply,
                                                                                        context.oldVersions.getOrDefault(
                                                                                                Constants.KEY_RULES, Collections.emptyMap()),
                                                                                        Constants.KEY_RULES,
                                                                                        targetSpaceEnum,
                                                                                        context.targetSpace,
                                                                                        listener),
                                                                        listener::onFailure)),
                                                listener::onFailure)),
                        listener::onFailure));
    }

    private void sapDeleteAsync(
            List<String> ids,
            int idx,
            String kind,
            Space targetSpaceEnum,
            String targetSpace,
            ActionListener<Void> listener) {
        if (idx >= ids.size()) {
            listener.onResponse(null);
            return;
        }
        String id = ids.get(idx);
        ActionListener<ActionResponse> itemListener =
                ActionListener.wrap(
                        r -> sapDeleteAsync(ids, idx + 1, kind, targetSpaceEnum, targetSpace, listener),
                        e -> {
                            log.warn(
                                    Constants.W_LOG_SAP_DELETE_RESOURCE_FAILED,
                                    kind,
                                    id,
                                    targetSpace,
                                    e.getMessage());
                            sapDeleteAsync(ids, idx + 1, kind, targetSpaceEnum, targetSpace, listener);
                        });

        if ("rule".equals(kind)) {
            this.securityAnalyticsService.deleteRule(id, targetSpaceEnum, itemListener);
        } else {
            this.securityAnalyticsService.deleteIntegration(id, targetSpaceEnum, itemListener);
        }
    }

    private void upsertSapResourcesAsync(
            Map<String, Map<String, Object>> resources,
            Map<String, Map<String, Object>> oldVersionsForType,
            String resourceType,
            Space targetSpaceEnum,
            String targetSpace,
            ActionListener<Void> listener) {
        List<Map.Entry<String, Map<String, Object>>> entries = new ArrayList<>(resources.entrySet());
        upsertSapEntryAsync(
                entries, 0, oldVersionsForType, resourceType, targetSpaceEnum, targetSpace, listener);
    }

    private void upsertSapEntryAsync(
            List<Map.Entry<String, Map<String, Object>>> entries,
            int idx,
            Map<String, Map<String, Object>> oldVersionsForType,
            String resourceType,
            Space targetSpaceEnum,
            String targetSpace,
            ActionListener<Void> listener) {
        if (idx >= entries.size()) {
            listener.onResponse(null);
            return;
        }
        Map.Entry<String, Map<String, Object>> entry = entries.get(idx);
        Map<String, Object> doc = entry.getValue();

        if (!doc.containsKey(Constants.KEY_DOCUMENT)) {
            upsertSapEntryAsync(
                    entries,
                    idx + 1,
                    oldVersionsForType,
                    resourceType,
                    targetSpaceEnum,
                    targetSpace,
                    listener);
            return;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> document = (Map<String, Object>) doc.get(Constants.KEY_DOCUMENT);
        RestRequest.Method method =
                oldVersionsForType.get(entry.getKey()) == null
                        ? RestRequest.Method.POST
                        : RestRequest.Method.PUT;

        ActionListener<ActionResponse> itemListener =
                ActionListener.wrap(
                        r ->
                                upsertSapEntryAsync(
                                        entries,
                                        idx + 1,
                                        oldVersionsForType,
                                        resourceType,
                                        targetSpaceEnum,
                                        targetSpace,
                                        listener),
                        e -> {
                            log.warn(
                                    Constants.W_LOG_SAP_SYNC_RESOURCE_FAILED,
                                    resourceType,
                                    entry.getKey(),
                                    targetSpace,
                                    e.getMessage());
                            upsertSapEntryAsync(
                                    entries,
                                    idx + 1,
                                    oldVersionsForType,
                                    resourceType,
                                    targetSpaceEnum,
                                    targetSpace,
                                    listener);
                        });

        if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
            this.securityAnalyticsService.upsertIntegration(
                    MAPPER.valueToTree(document), targetSpaceEnum, method, itemListener);
        } else {
            this.securityAnalyticsService.upsertRule(
                    MAPPER.valueToTree(document), targetSpaceEnum, method, itemListener);
        }
    }

    // ── Post-consolidation ───────────────────────────────────────────────────

    private void afterConsolidationPhase(
            PromotionContext context, ActionListener<MessageStatusResponse> listener) {
        this.spaceService.calculateAndUpdate(
                List.of(context.targetSpace),
                ActionListener.wrap(
                        changedSpaces -> {
                            // Promote loaded the content into this (coordinating) node's Engine only; the
                            // Engine socket is node-local. Broadcast a reload so every node loads the
                            // now-consolidated content into its own Engine, keyed off the target space's
                            // freshly recomputed hash. Reuses the same node-local, hash-gated loader as the
                            // STANDARD path; nodes that are down converge later via the cluster-state listener.
                            broadcastEngineReload();
                            listener.onResponse(
                                    new MessageStatusResponse(Constants.S_200_PROMOTION_COMPLETED, RestStatus.OK));
                        },
                        e -> respondWithError(listener, e)));
    }

    /**
     * Fires the cluster-wide Engine reload broadcast (fire-and-forget). Each node reloads any tracked
     * space whose hash changed; failures are logged and never affect the promote response.
     */
    private void broadcastEngineReload() {
        this.client.execute(
                ReloadEngineContentAction.INSTANCE,
                new ReloadEngineContentRequest(),
                ActionListener.wrap(
                        r -> log.debug(Constants.D_LOG_ENGINE_RELOAD_BROADCAST_SENT),
                        e -> log.warn(Constants.W_LOG_ENGINE_RELOAD_BROADCAST_FAILED, e.getMessage())));
    }

    // ── Rollback ─────────────────────────────────────────────────────────────

    private void rollbackAndFail(
            PromotionContext context, Exception cause, ActionListener<MessageStatusResponse> listener) {
        log.error(Constants.E_LOG_CONSOLIDATION_FAILED, cause.getMessage());
        rollbackChangesAsync(
                context,
                ActionListener.wrap(
                        v -> respondWithError(listener, wrapAsIOException(cause)),
                        rollbackError -> {
                            log.error("Rollback also failed: {}", rollbackError.getMessage());
                            respondWithError(listener, wrapAsIOException(cause));
                        }));
    }

    private void rollbackChangesAsync(PromotionContext context, ActionListener<Void> listener) {
        log.info(Constants.I_LOG_ROLLBACK_START, context.targetSpace, context.rollbackSteps.size());
        List<RollbackStep> steps = context.rollbackSteps;
        rollbackStepAsync(
                steps,
                steps.size() - 1,
                context,
                ActionListener.wrap(
                        v -> {
                            log.info(Constants.I_LOG_ROLLBACK_COMPLETE, context.targetSpace);
                            reconcileSapAfterRollbackAsync(context, listener);
                        },
                        e -> {
                            log.info(Constants.I_LOG_ROLLBACK_COMPLETE, context.targetSpace);
                            reconcileSapAfterRollbackAsync(context, listener);
                        }));
    }

    private void rollbackStepAsync(
            List<RollbackStep> steps, int idx, PromotionContext context, ActionListener<Void> listener) {
        if (idx < 0) {
            listener.onResponse(null);
            return;
        }
        RollbackStep step = steps.get(idx);
        rollbackCmStepAsync(
                step,
                context,
                ActionListener.wrap(
                        v -> {
                            log.debug(Constants.D_LOG_ROLLBACK_STEP_OK, step);
                            rollbackStepAsync(steps, idx - 1, context, listener);
                        },
                        e -> {
                            String index = this.spaceService.getIndexForResourceType(step.resourceType);
                            Collection<String> ids =
                                    (step.kind == RollbackStep.Kind.APPLY)
                                            ? context
                                                    .oldVersions
                                                    .getOrDefault(step.resourceType, Collections.emptyMap())
                                                    .keySet()
                                            : context
                                                    .deleteSnapshots
                                                    .getOrDefault(step.resourceType, Collections.emptyMap())
                                                    .keySet();
                            log.error(Constants.E_LOG_ROLLBACK_STEP_FAILED, step, index, ids, e.getMessage());
                            rollbackStepAsync(steps, idx - 1, context, listener);
                        }));
    }

    private void rollbackCmStepAsync(
            RollbackStep step, PromotionContext context, ActionListener<Void> listener) {
        String indexName = this.spaceService.getIndexForResourceType(step.resourceType);

        if (step.kind == RollbackStep.Kind.APPLY) {
            Map<String, Map<String, Object>> versions =
                    context.oldVersions.getOrDefault(step.resourceType, Collections.emptyMap());

            Set<String> toDelete = new HashSet<>();
            Map<String, Map<String, Object>> toRestore = new HashMap<>();

            for (Map.Entry<String, Map<String, Object>> entry : versions.entrySet()) {
                if (entry.getValue() == null) {
                    toDelete.add(entry.getKey());
                } else {
                    toRestore.put(entry.getKey(), entry.getValue());
                }
            }

            ActionListener<Void> afterDelete =
                    ActionListener.wrap(
                            v -> {
                                if (!toRestore.isEmpty()) {
                                    this.spaceService.promoteSpaceAsync(
                                            indexName, toRestore, context.targetSpace, listener);
                                } else {
                                    listener.onResponse(null);
                                }
                            },
                            listener::onFailure);

            if (!toDelete.isEmpty()) {
                this.spaceService.deleteResourcesAsync(
                        indexName, toDelete, context.targetSpace, afterDelete);
            } else {
                afterDelete.onResponse(null);
            }
        } else {
            Map<String, Map<String, Object>> snapshots =
                    context.deleteSnapshots.getOrDefault(step.resourceType, Collections.emptyMap());
            if (!snapshots.isEmpty()) {
                this.spaceService.promoteSpaceAsync(indexName, snapshots, context.targetSpace, listener);
            } else {
                listener.onResponse(null);
            }
        }
    }

    // ── SAP reconciliation after rollback (best-effort) ──────────────────────

    private void reconcileSapAfterRollbackAsync(
            PromotionContext context, ActionListener<Void> listener) {
        Space targetSpaceEnum = Space.fromValue(context.targetSpace);

        revertSapAppliedAsync(
                context.rulesToApply,
                context.oldVersions.getOrDefault(Constants.KEY_RULES, Collections.emptyMap()),
                Constants.KEY_RULES,
                targetSpaceEnum,
                ActionListener.wrap(
                        v ->
                                revertSapAppliedAsync(
                                        context.integrationsToApply,
                                        context.oldVersions.getOrDefault(
                                                Constants.KEY_INTEGRATIONS, Collections.emptyMap()),
                                        Constants.KEY_INTEGRATIONS,
                                        targetSpaceEnum,
                                        ActionListener.wrap(
                                                v2 ->
                                                        restoreSapDeletedAsync(
                                                                context.deleteSnapshots.getOrDefault(
                                                                        Constants.KEY_INTEGRATIONS, Collections.emptyMap()),
                                                                Constants.KEY_INTEGRATIONS,
                                                                targetSpaceEnum,
                                                                ActionListener.wrap(
                                                                        v3 ->
                                                                                restoreSapDeletedAsync(
                                                                                        context.deleteSnapshots.getOrDefault(
                                                                                                Constants.KEY_RULES, Collections.emptyMap()),
                                                                                        Constants.KEY_RULES,
                                                                                        targetSpaceEnum,
                                                                                        listener),
                                                                        e -> listener.onResponse(null))),
                                                e -> listener.onResponse(null))),
                        e -> listener.onResponse(null)));
    }

    private void revertSapAppliedAsync(
            Map<String, Map<String, Object>> resources,
            Map<String, Map<String, Object>> oldVersionsForType,
            String resourceType,
            Space targetSpaceEnum,
            ActionListener<Void> listener) {
        List<Map.Entry<String, Map<String, Object>>> entries = new ArrayList<>(resources.entrySet());
        revertSapAppliedEntryAsync(
                entries, 0, oldVersionsForType, resourceType, targetSpaceEnum, listener);
    }

    private void revertSapAppliedEntryAsync(
            List<Map.Entry<String, Map<String, Object>>> entries,
            int idx,
            Map<String, Map<String, Object>> oldVersionsForType,
            String resourceType,
            Space targetSpaceEnum,
            ActionListener<Void> listener) {
        if (idx >= entries.size()) {
            listener.onResponse(null);
            return;
        }
        String id = entries.get(idx).getKey();
        Map<String, Object> oldVersion = oldVersionsForType.get(id);

        ActionListener<Void> next =
                ActionListener.wrap(
                        v ->
                                revertSapAppliedEntryAsync(
                                        entries, idx + 1, oldVersionsForType, resourceType, targetSpaceEnum, listener),
                        e -> {
                            log.warn(Constants.W_LOG_SAP_ROLLBACK_FAILED, resourceType, id, e.getMessage());
                            revertSapAppliedEntryAsync(
                                    entries, idx + 1, oldVersionsForType, resourceType, targetSpaceEnum, listener);
                        });

        ActionListener<ActionResponse> sapListener =
                ActionListener.wrap(r -> next.onResponse(null), next::onFailure);

        if (oldVersion == null) {
            if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
                this.securityAnalyticsService.deleteIntegration(id, targetSpaceEnum, sapListener);
            } else {
                this.securityAnalyticsService.deleteRule(id, targetSpaceEnum, sapListener);
            }
            log.debug(Constants.D_LOG_SAP_ROLLBACK_DELETED, resourceType, id, targetSpaceEnum);
        } else if (oldVersion.containsKey(Constants.KEY_DOCUMENT)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> document = (Map<String, Object>) oldVersion.get(Constants.KEY_DOCUMENT);
            JsonNode docNode = MAPPER.valueToTree(document);
            if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
                this.securityAnalyticsService.upsertIntegration(
                        docNode, targetSpaceEnum, RestRequest.Method.PUT, sapListener);
            } else {
                this.securityAnalyticsService.upsertRule(
                        docNode, targetSpaceEnum, RestRequest.Method.PUT, sapListener);
            }
            log.debug(Constants.D_LOG_SAP_ROLLBACK_RESTORED, resourceType, id, targetSpaceEnum);
        } else {
            next.onResponse(null);
        }
    }

    private void restoreSapDeletedAsync(
            Map<String, Map<String, Object>> snapshots,
            String resourceType,
            Space targetSpaceEnum,
            ActionListener<Void> listener) {
        List<Map.Entry<String, Map<String, Object>>> entries = new ArrayList<>(snapshots.entrySet());
        restoreSapDeletedEntryAsync(entries, 0, resourceType, targetSpaceEnum, listener);
    }

    private void restoreSapDeletedEntryAsync(
            List<Map.Entry<String, Map<String, Object>>> entries,
            int idx,
            String resourceType,
            Space targetSpaceEnum,
            ActionListener<Void> listener) {
        if (idx >= entries.size()) {
            listener.onResponse(null);
            return;
        }
        String id = entries.get(idx).getKey();
        Map<String, Object> snapshot = entries.get(idx).getValue();

        ActionListener<Void> next =
                ActionListener.wrap(
                        v ->
                                restoreSapDeletedEntryAsync(
                                        entries, idx + 1, resourceType, targetSpaceEnum, listener),
                        e -> {
                            log.warn(
                                    Constants.W_LOG_SAP_ROLLBACK_RESTORE_DELETED_FAILED,
                                    resourceType,
                                    id,
                                    e.getMessage());
                            restoreSapDeletedEntryAsync(
                                    entries, idx + 1, resourceType, targetSpaceEnum, listener);
                        });

        if (snapshot != null && snapshot.containsKey(Constants.KEY_DOCUMENT)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> document = (Map<String, Object>) snapshot.get(Constants.KEY_DOCUMENT);
            JsonNode docNode = MAPPER.valueToTree(document);

            ActionListener<ActionResponse> sapListener =
                    ActionListener.wrap(
                            r -> {
                                log.debug(
                                        Constants.D_LOG_SAP_ROLLBACK_RESTORED_DELETED,
                                        resourceType,
                                        id,
                                        targetSpaceEnum);
                                next.onResponse(null);
                            },
                            next::onFailure);

            if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
                this.securityAnalyticsService.upsertIntegration(
                        docNode, targetSpaceEnum, RestRequest.Method.POST, sapListener);
            } else {
                this.securityAnalyticsService.upsertRule(
                        docNode, targetSpaceEnum, RestRequest.Method.POST, sapListener);
            }
        } else {
            next.onResponse(null);
        }
    }

    // ── Error handling ───────────────────────────────────────────────────────

    private void respondWithError(ActionListener<MessageStatusResponse> listener, Exception e) {
        RestResponse classified = TransportActionHelper.classifyException(e);
        if (classified != null) {
            RestStatus status = RestStatus.fromCode(classified.getStatus());
            if (status.getStatus() < 500) {
                log.warn(Constants.W_LOG_OPERATION_FAILED, "Promoting", "space", classified.getMessage());
            } else {
                log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "space", classified.getMessage());
            }
            listener.onResponse(new MessageStatusResponse(classified.getMessage(), status));
            return;
        }
        if (e instanceof IndexNotFoundException) {
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "index", e.getMessage());
        } else if (e instanceof IOException) {
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "IO", e.getMessage());
        } else {
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "space", e.getMessage());
        }
        listener.onResponse(
                new MessageStatusResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
    }

    private static IOException wrapAsIOException(Exception e) {
        return e instanceof IOException
                ? (IOException) e
                : new IOException("Consolidation failed: " + e.getMessage(), e);
    }

    // ── Pure-logic helpers (unchanged) ───────────────────────────────────────

    private boolean hasEngineRelatedChanges(PromotionContext context) {
        return !context.decodersToApply.isEmpty()
                || !context.kvdbsToApply.isEmpty()
                || !context.filtersToApply.isEmpty()
                || !context.decodersToDelete.isEmpty()
                || !context.kvdbsToDelete.isEmpty()
                || !context.filtersToDelete.isEmpty();
    }

    private void validatePromoteRequest(SpaceDiff spaceDiff) {
        Space sourceSpace = spaceDiff.getSpace();
        Space targetSpace = sourceSpace.promote();

        if (sourceSpace == targetSpace) {
            throw new IllegalArgumentException(
                    String.format(Locale.ROOT, Constants.E_400_UNPROMOTABLE_SPACE, sourceSpace));
        }

        SpaceDiff.Changes changes = spaceDiff.getChanges();

        if (changes == null) {
            throw new IllegalArgumentException("Changes object is required");
        }
        if (changes.getPolicy() == null
                || changes.getIntegrations() == null
                || changes.getKvdbs() == null
                || changes.getDecoders() == null
                || changes.getFilters() == null
                || changes.getRules() == null) {
            throw new IllegalArgumentException(
                    "All resource type lists (policy, integrations, kvdbs, decoders, filters, rules) are required in changes");
        }

        for (SpaceDiff.OperationItem item : changes.getPolicy()) {
            if (item.getOperation() != SpaceDiff.Operation.UPDATE) {
                throw new IllegalArgumentException(Constants.E_400_INVALID_PROMOTION_OPERATION_FOR_POLICY);
            }
        }
    }

    /**
     * Rejects a promotion that would leave a running detector with no enabled rules.
     *
     * <p>Only applies when promoting into {@code custom}, the space detectors resolve their rules
     * from. The decision is made on the resulting state, so an update that does not change a rule's
     * {@code enabled} flag never blocks, and a detector that already had no enabled rules is left
     * alone.
     *
     * @param spaceDiff the requested promotion.
     * @param listener receives the rejection message, or {@code null} when the promotion may proceed.
     */
    private void validateNoDetectorLeftEmptyAsync(
            SpaceDiff spaceDiff, ActionListener<String> listener) {
        Space sourceSpace = spaceDiff.getSpace();
        if (sourceSpace == null || sourceSpace.promote() != Space.CUSTOM) {
            listener.onResponse(null);
            return;
        }

        List<SpaceDiff.OperationItem> ruleChanges =
                spaceDiff.getChanges() == null ? null : spaceDiff.getChanges().getRules();
        if (ruleChanges == null || ruleChanges.isEmpty()) {
            listener.onResponse(null);
            return;
        }

        Set<String> changedRuleIds = new HashSet<>();
        Set<String> removedRuleIds = new HashSet<>();
        for (SpaceDiff.OperationItem item : ruleChanges) {
            changedRuleIds.add(item.getId());
            if (item.getOperation() == SpaceDiff.Operation.REMOVE) {
                removedRuleIds.add(item.getId());
            }
        }

        this.detectorLookupService.findDetectorsUsingRules(
                changedRuleIds,
                ActionListener.wrap(
                        affected -> {
                            if (affected.isEmpty()) {
                                listener.onResponse(null);
                                return;
                            }

                            Set<String> allRuleIds = new HashSet<>();
                            affected.forEach(detector -> allRuleIds.addAll(detector.ruleIds()));

                            this.detectorLookupService.fetchRuleEnabledStates(
                                    allRuleIds,
                                    Space.CUSTOM,
                                    ActionListener.wrap(
                                            currentEnabled ->
                                                    this.detectorLookupService.fetchRuleEnabledStates(
                                                            changedRuleIds,
                                                            sourceSpace,
                                                            ActionListener.wrap(
                                                                    incomingEnabled ->
                                                                            listener.onResponse(
                                                                                    rejectionMessage(
                                                                                            affected,
                                                                                            currentEnabled,
                                                                                            incomingEnabled,
                                                                                            removedRuleIds)),
                                                                    listener::onFailure)),
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    /**
     * Returns the rejection message naming every detector the promotion would empty, or {@code null}
     * when none would be.
     *
     * <p>A promotion carries the whole space diff, so a single one can empty several detectors, each
     * through a different rule. All of them are reported together, otherwise the user would fix one
     * per attempt without knowing how many are left. The listing is ordered by detector name so the
     * same promotion always produces the same message.
     *
     * @param detectors the enabled detectors referencing the promoted rules.
     * @param currentEnabled enabled state of those detectors' rules in the target space.
     * @param incomingEnabled enabled state carried by the promotion.
     * @param removedRuleIds rule ids the promotion deletes.
     * @return the message to return as {@code 400}, or {@code null} to let the promotion through.
     */
    static String rejectionMessage(
            List<DetectorLookupService.DetectorRules> detectors,
            Map<String, Boolean> currentEnabled,
            Map<String, Boolean> incomingEnabled,
            Set<String> removedRuleIds) {

        List<EmptiedDetector> emptied = new ArrayList<>();
        for (DetectorLookupService.DetectorRules detector : detectors) {
            if (DetectorRuleGuard.wouldLeaveDetectorEmpty(
                    detector.ruleIds(), currentEnabled, incomingEnabled, removedRuleIds)) {
                emptied.add(
                        new EmptiedDetector(
                                detector.name(),
                                culpritRule(detector, currentEnabled, incomingEnabled, removedRuleIds)));
            }
        }

        if (emptied.isEmpty()) {
            return null;
        }
        emptied.sort(Comparator.comparing(EmptiedDetector::detectorName));

        if (emptied.size() == 1) {
            EmptiedDetector only = emptied.get(0);
            return String.format(
                    Locale.ROOT,
                    Constants.E_400_PROMOTION_EMPTIES_DETECTOR,
                    only.culpritRule(),
                    only.detectorName());
        }

        String listing =
                emptied.stream()
                        .map(
                                item ->
                                        String.format(
                                                Locale.ROOT,
                                                "[%s] by disabling rule [%s]",
                                                item.detectorName(),
                                                item.culpritRule()))
                        .collect(Collectors.joining(", "));
        return String.format(
                Locale.ROOT, Constants.E_400_PROMOTION_EMPTIES_DETECTORS, emptied.size(), listing);
    }

    /**
     * Returns the first rule of the detector that the promotion takes away, which is the one worth
     * naming to the user.
     */
    private static String culpritRule(
            DetectorLookupService.DetectorRules detector,
            Map<String, Boolean> currentEnabled,
            Map<String, Boolean> incomingEnabled,
            Set<String> removedRuleIds) {
        return detector.ruleIds().stream()
                .filter(
                        id ->
                                Boolean.TRUE.equals(currentEnabled.get(id))
                                        && (removedRuleIds.contains(id)
                                                || Boolean.FALSE.equals(incomingEnabled.get(id))))
                .findFirst()
                .orElse("");
    }

    /** A detector the promotion would empty, with the rule that empties it. */
    private record EmptiedDetector(String detectorName, String culpritRule) {}

    // ── Inner classes ────────────────────────────────────────────────────────

    private record ResourceChangeEntry(
            List<SpaceDiff.OperationItem> items,
            String resourceType,
            Map<String, Map<String, Object>> resourcesToApply,
            Set<String> resourcesToDelete) {}

    /** Internal context class to hold promotion data and rollback state. */
    private static class PromotionContext {
        final JsonNode enginePayload;
        final Map<String, Map<String, Object>> policyToApply;
        final Map<String, Map<String, Object>> integrationsToApply;
        final Map<String, Map<String, Object>> kvdbsToApply;
        final Map<String, Map<String, Object>> decodersToApply;
        final Map<String, Map<String, Object>> filtersToApply;
        final Map<String, Map<String, Object>> rulesToApply;
        final Set<String> integrationsToDelete;
        final Set<String> kvdbsToDelete;
        final Set<String> decodersToDelete;
        final Set<String> filtersToDelete;
        final Set<String> rulesToDelete;
        final String targetSpace;

        final Map<String, Map<String, Map<String, Object>>> oldVersions = new HashMap<>();
        final Map<String, Map<String, Map<String, Object>>> deleteSnapshots = new HashMap<>();
        final List<RollbackStep> rollbackSteps = new ArrayList<>();

        PromotionContext(
                JsonNode enginePayload,
                Map<String, Map<String, Object>> policyToApply,
                Map<String, Map<String, Object>> integrationsToApply,
                Map<String, Map<String, Object>> kvdbsToApply,
                Map<String, Map<String, Object>> decodersToApply,
                Map<String, Map<String, Object>> filtersToApply,
                Map<String, Map<String, Object>> rulesToApply,
                Set<String> integrationsToDelete,
                Set<String> kvdbsToDelete,
                Set<String> decodersToDelete,
                Set<String> filtersToDelete,
                Set<String> rulesToDelete,
                String targetSpace) {
            this.enginePayload = enginePayload;
            this.policyToApply = policyToApply;
            this.integrationsToApply = integrationsToApply;
            this.kvdbsToApply = kvdbsToApply;
            this.decodersToApply = decodersToApply;
            this.filtersToApply = filtersToApply;
            this.rulesToApply = rulesToApply;
            this.integrationsToDelete = integrationsToDelete;
            this.kvdbsToDelete = kvdbsToDelete;
            this.decodersToDelete = decodersToDelete;
            this.filtersToDelete = filtersToDelete;
            this.rulesToDelete = rulesToDelete;
            this.targetSpace = targetSpace;
        }

        Map<String, Map<String, Object>> getApplyMap(String type) {
            return switch (type) {
                case Constants.KEY_POLICY -> policyToApply;
                case Constants.KEY_INTEGRATIONS -> integrationsToApply;
                case Constants.KEY_KVDBS -> kvdbsToApply;
                case Constants.KEY_DECODERS -> decodersToApply;
                case Constants.KEY_FILTERS -> filtersToApply;
                case Constants.KEY_RULES -> rulesToApply;
                default -> Collections.emptyMap();
            };
        }

        Set<String> getDeleteSet(String type) {
            return switch (type) {
                case Constants.KEY_INTEGRATIONS -> integrationsToDelete;
                case Constants.KEY_KVDBS -> kvdbsToDelete;
                case Constants.KEY_DECODERS -> decodersToDelete;
                case Constants.KEY_FILTERS -> filtersToDelete;
                case Constants.KEY_RULES -> rulesToDelete;
                default -> Collections.emptySet();
            };
        }
    }

    private record RollbackStep(Kind kind, String resourceType) {
        enum Kind {
            APPLY,
            DELETE
        }

        @Override
        public String toString() {
            return kind + "/" + resourceType;
        }
    }
}
