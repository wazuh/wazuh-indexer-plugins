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
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.rest.RestRequest;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.PostPromoteAction;
import com.wazuh.contentmanager.action.PostPromoteRequest;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
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

    @Inject
    public TransportPostPromoteAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SpaceService spaceService,
            EngineService engine,
            SecurityAnalyticsService securityAnalyticsService) {
        super(PostPromoteAction.NAME, transportService, actionFilters, PostPromoteRequest::new);
        this.spaceService = spaceService;
        this.engine = engine;
        this.securityAnalyticsService = securityAnalyticsService;
    }

    @Override
    protected void doExecute(
            Task task, PostPromoteRequest request, ActionListener<MessageStatusResponse> listener) {
        // 1. Check if engine service exists
        if (this.engine == null) {
            log.error(Constants.E_LOG_ENGINE_IS_NULL);
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
            return;
        }

        // 2. Check request body exists
        String body = request.getBody();
        if (body == null || body.isBlank()) {
            listener.onResponse(
                    new MessageStatusResponse(Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
            return;
        }

        try {
            // 1. Validation Phase - Validate payload
            ObjectMapper mapper = new ObjectMapper();
            SpaceDiff spaceDiff = mapper.readValue(body, SpaceDiff.class);
            this.validatePromoteRequest(spaceDiff);

            // 2. Gathering Phase - Build the engine payload
            PromotionContext context = this.gatherPromotionData(spaceDiff);

            // 3. Validation Phase - Invoke engine validation
            Space targetSpace = spaceDiff.getSpace().promote();
            PlainActionFuture<Boolean> hasResourcesFuture = new PlainActionFuture<>();
            this.spaceService.hasEngineResources(targetSpace, hasResourcesFuture);
            if ((targetSpace == Space.TEST || targetSpace == Space.CUSTOM)
                    && (this.hasEngineRelatedChanges(context) || hasResourcesFuture.actionGet())) {
                RestResponse engineResponse = this.engine.promote(context.enginePayload);

                if (engineResponse.getStatus() != RestStatus.OK.getStatus()
                        && engineResponse.getStatus() != RestStatus.ACCEPTED.getStatus()) {
                    log.warn(Constants.W_LOG_VALIDATION_FAILED, engineResponse.getMessage());
                    log.debug(
                            Constants.D_LOG_ENGINE_REJECTED_PAYLOAD,
                            mapper.writeValueAsString(context.enginePayload));
                    listener.onResponse(
                            new MessageStatusResponse(
                                    engineResponse.getMessage(), RestStatus.fromCode(engineResponse.getStatus())));
                    return;
                }
                log.debug(Constants.D_LOG_ENGINE_VALIDATION_COMPLETE, targetSpace);
            }

            // 4. Consolidation Phase
            this.consolidateChanges(context);

            PlainActionFuture<Set<String>> hashFuture = new PlainActionFuture<>();
            this.spaceService.calculateAndUpdate(List.of(targetSpace.toString()), hashFuture);
            hashFuture.actionGet();

            // 5. Response Phase
            listener.onResponse(
                    new MessageStatusResponse(Constants.S_200_PROMOTION_COMPLETED, RestStatus.OK));
        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            listener.onResponse(new MessageStatusResponse(e.getMessage(), RestStatus.BAD_REQUEST));
        } catch (ValueInstantiationException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
            listener.onResponse(new MessageStatusResponse(message, RestStatus.BAD_REQUEST));
        } catch (IndexNotFoundException e) {
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "index", e.getMessage());
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
        } catch (IOException e) {
            OpenSearchSecurityException secEx = extractSecurityException(e);
            if (secEx != null) {
                listener.onResponse(new MessageStatusResponse(secEx.getMessage(), secEx.status()));
                return;
            }
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "IO", e.getMessage());
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
        } catch (Exception e) {
            OpenSearchSecurityException secEx = extractSecurityException(e);
            if (secEx != null) {
                listener.onResponse(new MessageStatusResponse(secEx.getMessage(), secEx.status()));
                return;
            }
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "space", e.getMessage());
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
        }
    }

    private static OpenSearchSecurityException extractSecurityException(Throwable throwable) {
        Throwable cause = throwable;
        while (cause != null) {
            if (cause instanceof OpenSearchSecurityException) {
                return (OpenSearchSecurityException) cause;
            }
            cause = cause.getCause();
        }
        return null;
    }

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

    private PromotionContext gatherPromotionData(SpaceDiff spaceDiff) throws IOException {
        Space sourceSpace = spaceDiff.getSpace();
        Space targetSpace = sourceSpace.promote();
        SpaceDiff.Changes changes = spaceDiff.getChanges();

        PlainActionFuture<Map<String, Object>> policyFuture = new PlainActionFuture<>();
        this.spaceService.getPolicy(sourceSpace.toString(), policyFuture);
        Map<String, Object> policyDocument = policyFuture.actionGet();
        if (policyDocument == null) {
            throw new IOException("Policy document not found for source space: " + sourceSpace);
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

        this.processResourceChanges(
                changes.getPolicy(),
                Constants.KEY_POLICY,
                policyToApply,
                HashSet.newHashSet(0),
                sourceSpace.toString(),
                targetSpace.toString());
        this.processResourceChanges(
                changes.getIntegrations(),
                Constants.KEY_INTEGRATIONS,
                integrationsToApply,
                integrationsToDelete,
                sourceSpace.toString(),
                targetSpace.toString());
        this.processResourceChanges(
                changes.getKvdbs(),
                Constants.KEY_KVDBS,
                kvdbsToApply,
                kvdbsToDelete,
                sourceSpace.toString(),
                targetSpace.toString());
        this.processResourceChanges(
                changes.getDecoders(),
                Constants.KEY_DECODERS,
                decodersToApply,
                decodersToDelete,
                sourceSpace.toString(),
                targetSpace.toString());
        this.processResourceChanges(
                changes.getFilters(),
                Constants.KEY_FILTERS,
                filtersToApply,
                filtersToDelete,
                sourceSpace.toString(),
                targetSpace.toString());
        this.processResourceChanges(
                changes.getRules(),
                Constants.KEY_RULES,
                rulesToApply,
                rulesToDelete,
                sourceSpace.toString(),
                targetSpace.toString());

        PlainActionFuture<JsonNode> enginePayloadFuture = new PlainActionFuture<>();
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
                enginePayloadFuture);
        JsonNode enginePayload = enginePayloadFuture.actionGet();

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

        for (String type : APPLY_RESOURCE_TYPES) {
            this.captureOldVersions(context, type);
        }
        for (String type : DELETE_RESOURCE_TYPES) {
            this.captureDeleteSnapshots(context, type);
        }

        return context;
    }

    private void captureOldVersions(PromotionContext context, String resourceType)
            throws IOException {
        Map<String, Map<String, Object>> resourcesToApply = context.getApplyMap(resourceType);
        if (resourcesToApply.isEmpty()) {
            return;
        }
        String indexName = this.spaceService.getIndexForResourceType(resourceType);
        Map<String, Map<String, Object>> dest =
                context.oldVersions.computeIfAbsent(resourceType, k -> new HashMap<>());

        for (String docId : resourcesToApply.keySet()) {
            try {
                PlainActionFuture<Map<String, Object>> existingFuture = new PlainActionFuture<>();
                if (resourceType.equals(Constants.KEY_POLICY)) {
                    this.spaceService.getPolicy(context.targetSpace, existingFuture);
                } else {
                    this.spaceService.getDocument(indexName, context.targetSpace, docId, existingFuture);
                }
                dest.put(docId, existingFuture.actionGet());
            } catch (Exception e) {
                log.warn(Constants.W_LOG_SNAPSHOT_OLD_VERSION_FAILED, docId, resourceType, e.getMessage());
                throw e instanceof IOException ? (IOException) e : new IOException(e.getMessage(), e);
            }
        }
    }

    private void captureDeleteSnapshots(PromotionContext context, String resourceType)
            throws IOException {
        Set<String> idsToDelete = context.getDeleteSet(resourceType);
        if (idsToDelete.isEmpty()) {
            return;
        }
        String indexName = this.spaceService.getIndexForResourceType(resourceType);
        Map<String, Map<String, Object>> dest =
                context.deleteSnapshots.computeIfAbsent(resourceType, k -> new HashMap<>());

        for (String docId : idsToDelete) {
            try {
                PlainActionFuture<Map<String, Object>> existingFuture = new PlainActionFuture<>();
                this.spaceService.getDocument(indexName, context.targetSpace, docId, existingFuture);
                Map<String, Object> existing = existingFuture.actionGet();
                if (existing != null) {
                    dest.put(docId, existing);
                }
            } catch (Exception e) {
                log.error(
                        Constants.E_LOG_SNAPSHOT_DELETE_TARGET_FAILED, docId, resourceType, e.getMessage());
                throw e instanceof IOException ? (IOException) e : new IOException(e.getMessage(), e);
            }
        }
    }

    private void processResourceChanges(
            List<SpaceDiff.OperationItem> items,
            String resourceType,
            Map<String, Map<String, Object>> resourcesToApply,
            Set<String> resourcesToDelete,
            String sourceSpace,
            String targetSpace)
            throws IOException {

        String indexName = this.spaceService.getIndexForResourceType(resourceType);
        if (indexName == null) {
            throw new IllegalArgumentException("Unknown resource type: " + resourceType);
        }

        for (SpaceDiff.OperationItem item : items) {
            String resourceId = item.getId();
            SpaceDiff.Operation operation = item.getOperation();

            switch (operation) {
                case ADD -> {
                    PlainActionFuture<Map<String, Object>> srcFuture = new PlainActionFuture<>();
                    this.spaceService.getDocument(indexName, sourceSpace, resourceId, srcFuture);
                    Map<String, Object> sourceDoc = srcFuture.actionGet();
                    if (sourceDoc == null) {
                        throw new IOException(
                                "Resource '"
                                        + resourceId
                                        + "' not found in "
                                        + resourceType
                                        + " for ADD operation");
                    }

                    @SuppressWarnings("unchecked")
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

                    PlainActionFuture<Map<String, Object>> tgtFuture = new PlainActionFuture<>();
                    this.spaceService.getDocument(indexName, targetSpace, resourceId, tgtFuture);
                    Map<String, Object> targetDoc = tgtFuture.actionGet();
                    if (targetDoc != null) {
                        @SuppressWarnings("unchecked")
                        Map<String, String> targetDocSpace =
                                (Map<String, String>) targetDoc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                        String targetDocSpaceName = targetDocSpace.get(Constants.KEY_NAME);
                        if (targetSpace.equals(targetDocSpaceName)) {
                            throw new IllegalArgumentException(
                                    "Resource '"
                                            + resourceId
                                            + "' already exists in target space '"
                                            + targetSpace
                                            + "', use UPDATE operation instead");
                        }
                    }

                    resourcesToApply.put(resourceId, sourceDoc);
                }
                case UPDATE -> {
                    PlainActionFuture<Map<String, Object>> updFuture = new PlainActionFuture<>();
                    if (resourceType.equals(Constants.KEY_POLICY)) {
                        this.spaceService.getPolicy(sourceSpace, updFuture);
                    } else {
                        this.spaceService.getDocument(indexName, sourceSpace, resourceId, updFuture);
                    }
                    Map<String, Object> sourceDoc = updFuture.actionGet();
                    if (sourceDoc == null) {
                        throw new IOException(
                                "Resource '"
                                        + resourceId
                                        + "' not found in "
                                        + resourceType
                                        + " for UPDATE operation");
                    }

                    @SuppressWarnings("unchecked")
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
                    resourcesToApply.put(resourceId, sourceDoc);
                }
                case REMOVE -> {
                    PlainActionFuture<Map<String, Object>> rmFuture = new PlainActionFuture<>();
                    this.spaceService.getDocument(indexName, targetSpace, resourceId, rmFuture);
                    Map<String, Object> targetDoc = rmFuture.actionGet();
                    if (targetDoc != null) {
                        @SuppressWarnings("unchecked")
                        Map<String, String> targetDocSpace =
                                (Map<String, String>) targetDoc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
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
                }
            }
        }
    }

    private void consolidateChanges(PromotionContext context) throws IOException {
        try {
            this.doConsolidate(context);
        } catch (Exception e) {
            log.error(Constants.E_LOG_CONSOLIDATION_FAILED, e.getMessage());
            this.rollbackChanges(context);
            throw e instanceof IOException
                    ? (IOException) e
                    : new IOException("Consolidation failed: " + e.getMessage(), e);
        }
    }

    private void promoteIfNotEmpty(
            String resourceType, Map<String, Map<String, Object>> resources, PromotionContext context)
            throws IOException {
        if (!resources.isEmpty()) {
            PlainActionFuture<Void> promoteFuture = new PlainActionFuture<>();
            this.spaceService.promoteSpace(
                    this.spaceService.getIndexForResourceType(resourceType),
                    resources,
                    context.targetSpace,
                    promoteFuture);
            promoteFuture.actionGet();
            context.rollbackSteps.add(new RollbackStep(RollbackStep.Kind.APPLY, resourceType));
        }
    }

    private void deleteIfNotEmpty(String resourceType, Set<String> ids, PromotionContext context)
            throws IOException {
        if (!ids.isEmpty()) {
            PlainActionFuture<Void> deleteFuture = new PlainActionFuture<>();
            this.spaceService.deleteResources(
                    this.spaceService.getIndexForResourceType(resourceType),
                    ids,
                    context.targetSpace,
                    deleteFuture);
            deleteFuture.actionGet();
            context.rollbackSteps.add(new RollbackStep(RollbackStep.Kind.DELETE, resourceType));
        }
    }

    private void doConsolidate(PromotionContext context) throws IOException {
        Space targetSpaceEnum = Space.fromValue(context.targetSpace);
        ObjectMapper mapper = new ObjectMapper();

        for (String type : APPLY_RESOURCE_TYPES) {
            this.promoteIfNotEmpty(type, context.getApplyMap(type), context);
        }

        for (String type : DELETE_RESOURCE_TYPES) {
            this.deleteIfNotEmpty(type, context.getDeleteSet(type), context);
        }

        // Best-effort SAP synchronization
        for (String ruleId : context.rulesToDelete) {
            try {
                this.securityAnalyticsService.deleteRule(ruleId, targetSpaceEnum);
            } catch (Exception e) {
                log.warn(
                        Constants.W_LOG_SAP_DELETE_RESOURCE_FAILED,
                        "rule",
                        ruleId,
                        context.targetSpace,
                        e.getMessage());
            }
        }

        for (String integrationId : context.integrationsToDelete) {
            try {
                this.securityAnalyticsService.deleteIntegration(integrationId, targetSpaceEnum);
            } catch (Exception e) {
                log.warn(
                        Constants.W_LOG_SAP_DELETE_RESOURCE_FAILED,
                        "integration",
                        integrationId,
                        context.targetSpace,
                        e.getMessage());
            }
        }

        this.upsertSapResources(
                context.integrationsToApply,
                context.oldVersions.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyMap()),
                Constants.KEY_INTEGRATIONS,
                targetSpaceEnum,
                mapper,
                context.targetSpace);

        this.upsertSapResources(
                context.rulesToApply,
                context.oldVersions.getOrDefault(Constants.KEY_RULES, Collections.emptyMap()),
                Constants.KEY_RULES,
                targetSpaceEnum,
                mapper,
                context.targetSpace);
    }

    private void upsertSapResources(
            Map<String, Map<String, Object>> resources,
            Map<String, Map<String, Object>> oldVersionsForType,
            String resourceType,
            Space targetSpaceEnum,
            ObjectMapper mapper,
            String targetSpace) {
        for (Map.Entry<String, Map<String, Object>> entry : resources.entrySet()) {
            Map<String, Object> doc = entry.getValue();
            if (doc.containsKey(Constants.KEY_DOCUMENT)) {
                @SuppressWarnings("unchecked")
                Map<String, Object> document = (Map<String, Object>) doc.get(Constants.KEY_DOCUMENT);
                try {
                    RestRequest.Method method =
                            oldVersionsForType.get(entry.getKey()) == null
                                    ? RestRequest.Method.POST
                                    : RestRequest.Method.PUT;
                    if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
                        this.securityAnalyticsService.upsertIntegration(
                                mapper.valueToTree(document), targetSpaceEnum, method);
                    } else {
                        this.securityAnalyticsService.upsertRule(
                                mapper.valueToTree(document), targetSpaceEnum, method);
                    }
                } catch (Exception e) {
                    log.warn(
                            Constants.W_LOG_SAP_SYNC_RESOURCE_FAILED,
                            resourceType,
                            entry.getKey(),
                            targetSpace,
                            e.getMessage());
                }
            }
        }
    }

    private void rollbackChanges(PromotionContext context) {
        log.info(Constants.I_LOG_ROLLBACK_START, context.targetSpace, context.rollbackSteps.size());

        ListIterator<RollbackStep> it =
                context.rollbackSteps.listIterator(context.rollbackSteps.size());

        while (it.hasPrevious()) {
            RollbackStep step = it.previous();
            try {
                this.rollbackCmStep(step, context);
                log.debug(Constants.D_LOG_ROLLBACK_STEP_OK, step);
            } catch (Exception e) {
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
            }
        }

        log.info(Constants.I_LOG_ROLLBACK_COMPLETE, context.targetSpace);
        this.reconcileSapAfterRollback(context);
    }

    private void rollbackCmStep(RollbackStep step, PromotionContext context) throws IOException {
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

            if (!toDelete.isEmpty()) {
                PlainActionFuture<Void> delFuture = new PlainActionFuture<>();
                this.spaceService.deleteResources(indexName, toDelete, context.targetSpace, delFuture);
                delFuture.actionGet();
            }
            if (!toRestore.isEmpty()) {
                PlainActionFuture<Void> restoreFuture = new PlainActionFuture<>();
                this.spaceService.promoteSpace(indexName, toRestore, context.targetSpace, restoreFuture);
                restoreFuture.actionGet();
            }
        } else {
            Map<String, Map<String, Object>> snapshots =
                    context.deleteSnapshots.getOrDefault(step.resourceType, Collections.emptyMap());
            if (!snapshots.isEmpty()) {
                PlainActionFuture<Void> snapFuture = new PlainActionFuture<>();
                this.spaceService.promoteSpace(indexName, snapshots, context.targetSpace, snapFuture);
                snapFuture.actionGet();
            }
        }
    }

    private void reconcileSapAfterRollback(PromotionContext context) {
        Space targetSpaceEnum = Space.fromValue(context.targetSpace);
        ObjectMapper mapper = new ObjectMapper();

        this.revertSapApplied(
                context.rulesToApply,
                context.oldVersions.getOrDefault(Constants.KEY_RULES, Collections.emptyMap()),
                Constants.KEY_RULES,
                targetSpaceEnum,
                mapper);

        this.revertSapApplied(
                context.integrationsToApply,
                context.oldVersions.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyMap()),
                Constants.KEY_INTEGRATIONS,
                targetSpaceEnum,
                mapper);

        this.restoreSapDeleted(
                context.deleteSnapshots.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyMap()),
                Constants.KEY_INTEGRATIONS,
                targetSpaceEnum,
                mapper);

        this.restoreSapDeleted(
                context.deleteSnapshots.getOrDefault(Constants.KEY_RULES, Collections.emptyMap()),
                Constants.KEY_RULES,
                targetSpaceEnum,
                mapper);
    }

    private void revertSapApplied(
            Map<String, Map<String, Object>> resources,
            Map<String, Map<String, Object>> oldVersionsForType,
            String resourceType,
            Space targetSpaceEnum,
            ObjectMapper mapper) {

        for (Map.Entry<String, Map<String, Object>> entry : resources.entrySet()) {
            String id = entry.getKey();
            Map<String, Object> oldVersion = oldVersionsForType.get(id);

            try {
                if (oldVersion == null) {
                    if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
                        this.securityAnalyticsService.deleteIntegration(id, targetSpaceEnum);
                    } else {
                        this.securityAnalyticsService.deleteRule(id, targetSpaceEnum);
                    }
                    log.debug(Constants.D_LOG_SAP_ROLLBACK_DELETED, resourceType, id, targetSpaceEnum);
                } else if (oldVersion.containsKey(Constants.KEY_DOCUMENT)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> document =
                            (Map<String, Object>) oldVersion.get(Constants.KEY_DOCUMENT);
                    JsonNode docNode = mapper.valueToTree(document);
                    if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
                        this.securityAnalyticsService.upsertIntegration(
                                docNode, targetSpaceEnum, RestRequest.Method.PUT);
                    } else {
                        this.securityAnalyticsService.upsertRule(
                                docNode, targetSpaceEnum, RestRequest.Method.PUT);
                    }
                    log.debug(Constants.D_LOG_SAP_ROLLBACK_RESTORED, resourceType, id, targetSpaceEnum);
                }
            } catch (Exception e) {
                log.warn(Constants.W_LOG_SAP_ROLLBACK_FAILED, resourceType, id, e.getMessage());
            }
        }
    }

    private void restoreSapDeleted(
            Map<String, Map<String, Object>> snapshots,
            String resourceType,
            Space targetSpaceEnum,
            ObjectMapper mapper) {

        for (Map.Entry<String, Map<String, Object>> entry : snapshots.entrySet()) {
            String id = entry.getKey();
            Map<String, Object> snapshot = entry.getValue();

            try {
                if (snapshot != null && snapshot.containsKey(Constants.KEY_DOCUMENT)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> document = (Map<String, Object>) snapshot.get(Constants.KEY_DOCUMENT);
                    JsonNode docNode = mapper.valueToTree(document);
                    if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
                        this.securityAnalyticsService.upsertIntegration(
                                docNode, targetSpaceEnum, RestRequest.Method.POST);
                    } else {
                        this.securityAnalyticsService.upsertRule(
                                docNode, targetSpaceEnum, RestRequest.Method.POST);
                    }
                    log.debug(
                            Constants.D_LOG_SAP_ROLLBACK_RESTORED_DELETED, resourceType, id, targetSpaceEnum);
                }
            } catch (Exception e) {
                log.warn(
                        Constants.W_LOG_SAP_ROLLBACK_RESTORE_DELETED_FAILED, resourceType, id, e.getMessage());
            }
        }
    }

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
