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
package com.wazuh.contentmanager.rest.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.ValueInstantiationException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.*;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.model.SpaceDiff;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * POST /_plugins/_content_manager/promote
 *
 * <p>Execute promotion process in the local engine. Possible HTTP responses:
 *
 * <pre>
 * - 200 Accepted: Wazuh Engine replied with a successful response.
 * - 400 Bad Request: Wazuh Engine replied with an error response.
 * - 500 Internal Server Error: Unexpected error during processing. Wazuh Engine did not respond.
 * </pre>
 */
public class RestPostPromoteAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostPromoteAction.class);
    private static final String ENDPOINT_NAME = "content_manager_promote";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/promote";

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

    private final EngineService engine;
    private SpaceService spaceService;
    private final SecurityAnalyticsService securityAnalyticsService;

    /**
     * Constructor.
     *
     * @param engine The service instance to communicate with the local engine service.
     * @param spaceService The service instance to manage space operations.
     * @param securityAnalyticsService The service instance to communicate with the Security Analytics
     *     plugin.
     */
    public RestPostPromoteAction(
            EngineService engine,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService) {
        this.engine = engine;
        this.spaceService = spaceService;
        this.securityAnalyticsService = securityAnalyticsService;
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the update endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.PROMOTE_URI)
                        .method(RestRequest.Method.POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Handles incoming requests.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the promotion operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            RestResponse response = this.handleRequest(request);
            channel.sendResponse(response.toBytesRestResponse());
        };
    }

    /**
     * Sets the policy hash service for testing purposes.
     *
     * @param spaceService the SpaceService instance to use
     */
    public void setPolicyHashService(SpaceService spaceService) {
        this.spaceService = spaceService;
    }

    /**
     * Execute the space promotion operation.
     *
     * @param request incoming request
     * @return a RestResponse
     */
    public RestResponse handleRequest(RestRequest request) {
        // 1. Check if engine service exists
        if (this.engine == null) {
            log.error(Constants.E_LOG_ENGINE_IS_NULL);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // 2. Check request's payload exists
        if (request == null || !request.hasContent()) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        try {
            // 1. Validation Phase - Validate payload
            ObjectMapper mapper = new ObjectMapper();
            SpaceDiff spaceDiff = mapper.readValue(request.content().streamInput(), SpaceDiff.class);
            this.validatePromoteRequest(spaceDiff);

            // 2. Gathering Phase - Build the engine payload
            PromotionContext context = this.gatherPromotionData(spaceDiff);

            // 3. Validation Phase - Invoke engine validation only for test promotions
            if (spaceDiff.getSpace().promote() == Space.TEST) {
                RestResponse engineResponse = this.engine.promote(context.enginePayload);

                // Check if engine validation was successful
                if (engineResponse.getStatus() != RestStatus.OK.getStatus()
                        && engineResponse.getStatus() != RestStatus.ACCEPTED.getStatus()) {
                    log.warn(Constants.E_LOG_ENGINE_VALIDATION, engineResponse.getMessage());
                    log.error(mapper.writeValueAsString(context.enginePayload));
                    return engineResponse;
                }
                log.info(
                        "Engine validation for space [{}] completed successfully.",
                        spaceDiff.getSpace().promote());
            }

            // 4. Consolidation Phase - Apply changes to target space
            this.consolidateChanges(context);

            // After successful promotion, recalculate policy hashes for the promoted space
            this.spaceService.calculateAndUpdate(List.of(spaceDiff.getSpace().promote().toString()));

            // 5. Response Phase - Reply with success
            return new RestResponse(Constants.S_200_PROMOTION_COMPLETED, RestStatus.OK.getStatus());
        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (ValueInstantiationException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            // Extract the root cause message for better error reporting
            String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
            return new RestResponse(message, RestStatus.BAD_REQUEST.getStatus());
        } catch (IndexNotFoundException e) {
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "index", e.getMessage());
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        } catch (IOException e) {
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "IO", e.getMessage());
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        } catch (Exception e) {
            log.error(Constants.E_LOG_OPERATION_FAILED, "promoting", "space", e.getMessage());
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Validates the promote request payload.
     *
     * @param spaceDiff The space diff request to validate.
     * @throws IllegalArgumentException If validation fails.
     */
    private void validatePromoteRequest(SpaceDiff spaceDiff) {
        Space sourceSpace = spaceDiff.getSpace();
        Space targetSpace = sourceSpace.promote();

        // Validate that the source space can be promoted
        if (sourceSpace == targetSpace) {
            throw new IllegalArgumentException(
                    String.format(Locale.ROOT, Constants.E_400_UNPROMOTABLE_SPACE, sourceSpace));
        }

        SpaceDiff.Changes changes = spaceDiff.getChanges();

        // Validate that all required change lists are present
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

        // Validate policy operations - only UPDATE is allowed
        for (SpaceDiff.OperationItem item : changes.getPolicy()) {
            if (item.getOperation() != SpaceDiff.Operation.UPDATE) {
                throw new IllegalArgumentException(Constants.E_400_INVALID_PROMOTION_OPERATION_FOR_POLICY);
            }
        }
    }

    /**
     * Gathers all necessary data for the promotion operation. This method fetches all resources from
     * the target space and applies the modifications from the source space. It also captures
     * pre-promotion snapshots of target-space resources for rollback support.
     *
     * @param spaceDiff The space diff request.
     * @return A PromotionContext containing the engine payload, consolidation data, and rollback
     *     snapshots.
     * @throws IOException If any data gathering fails.
     */
    private PromotionContext gatherPromotionData(SpaceDiff spaceDiff) throws IOException {
        Space sourceSpace = spaceDiff.getSpace();
        Space targetSpace = sourceSpace.promote();
        SpaceDiff.Changes changes = spaceDiff.getChanges();

        // Fetch the source policy
        Map<String, Object> policyDocument = this.spaceService.getPolicy(sourceSpace.toString());
        if (policyDocument == null) {
            throw new IOException("Policy document not found for source space: " + sourceSpace);
        }

        // Maps to track resources to apply (ADD/UPDATE) - from source space
        Map<String, Map<String, Object>> policyToApply = new HashMap<>();
        Map<String, Map<String, Object>> integrationsToApply = new HashMap<>();
        Map<String, Map<String, Object>> kvdbsToApply = new HashMap<>();
        Map<String, Map<String, Object>> decodersToApply = new HashMap<>();
        Map<String, Map<String, Object>> filtersToApply = new HashMap<>();
        Map<String, Map<String, Object>> rulesToApply = new HashMap<>();

        // Sets to track resources to delete
        Set<String> integrationsToDelete = new HashSet<>();
        Set<String> kvdbsToDelete = new HashSet<>();
        Set<String> decodersToDelete = new HashSet<>();
        Set<String> filtersToDelete = new HashSet<>();
        Set<String> rulesToDelete = new HashSet<>();

        // Process each resource type
        this.processResourceChanges(
                changes.getPolicy(),
                Constants.KEY_POLICY,
                policyToApply,
                HashSet.newHashSet(0), // Policies cannot be removed.
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

        // Build engine payload with all target space resources + modifications
        JsonNode enginePayload =
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
                        filtersToDelete);

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

        // Capture pre-promotion snapshots for rollback support
        for (String type : APPLY_RESOURCE_TYPES) {
            this.captureOldVersions(context, type);
        }
        for (String type : DELETE_RESOURCE_TYPES) {
            this.captureDeleteSnapshots(context, type);
        }

        return context;
    }

    /**
     * Captures the current target-space version of each resource about to be added or updated. If the
     * resource does not yet exist in the target space the entry is stored as {@code null}, indicating
     * a pure ADD operation for rollback purposes.
     *
     * @param context The promotion context.
     * @param resourceType The resource type key.
     * @throws IOException If the snapshot cannot be captured.
     */
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
                Map<String, Object> existing;
                if (resourceType.equals(Constants.KEY_POLICY)) {
                    existing = this.spaceService.getPolicy(context.targetSpace);
                } else {
                    existing = this.spaceService.getDocument(indexName, context.targetSpace, docId);
                }
                dest.put(docId, existing); // null means it was a new addition
            } catch (IOException e) {
                log.warn(
                        "Failed to snapshot old version of [{}] in [{}]: {}",
                        docId,
                        resourceType,
                        e.getMessage());
                throw e;
            }
        }
    }

    /**
     * Captures the current target-space version of each resource about to be deleted, so it can be
     * restored on rollback.
     *
     * @param context The promotion context.
     * @param resourceType The resource type key.
     * @throws IOException If the snapshot cannot be captured.
     */
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
                Map<String, Object> existing =
                        this.spaceService.getDocument(indexName, context.targetSpace, docId);
                if (existing != null) {
                    dest.put(docId, existing);
                }
            } catch (IOException e) {
                log.error(
                        "Failed to snapshot delete target [{}] in [{}]: {}. Aborting promotion.",
                        docId,
                        resourceType,
                        e.getMessage());
                throw e;
            }
        }
    }

    /**
     * Processes resource changes for a specific resource type.
     *
     * @param items The list of operation items.
     * @param resourceType The resource type key.
     * @param resourcesToApply Map to collect resources (from source) to apply to target.
     * @param resourcesToDelete Set to collect resource IDs to delete.
     * @param sourceSpace The source space name.
     * @param targetSpace The target space name.
     * @throws IOException If resource validation fails.
     */
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
                    // ADD: Resource exists in source space but NOT in target space
                    Map<String, Object> sourceDoc =
                            this.spaceService.getDocument(indexName, sourceSpace, resourceId);
                    if (sourceDoc == null) {
                        throw new IOException(
                                "Resource '"
                                        + resourceId
                                        + "' not found in "
                                        + resourceType
                                        + " for ADD operation");
                    }

                    // Verify it's in the source space
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

                    // Verify it does NOT exist in target space
                    Map<String, Object> targetDoc =
                            this.spaceService.getDocument(indexName, targetSpace, resourceId);
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

                    // Add to apply list
                    resourcesToApply.put(resourceId, sourceDoc);
                }
                case UPDATE -> {
                    Map<String, Object> sourceDoc;
                    // Fetch the source policy
                    if (resourceType.equals(Constants.KEY_POLICY)) {
                        sourceDoc = this.spaceService.getPolicy(sourceSpace);
                    } else {
                        // UPDATE: Resource exists in BOTH source and target spaces
                        sourceDoc = this.spaceService.getDocument(indexName, sourceSpace, resourceId);
                    }
                    if (sourceDoc == null) {
                        throw new IOException(
                                "Resource '"
                                        + resourceId
                                        + "' not found in "
                                        + resourceType
                                        + " for UPDATE operation");
                    }

                    // Verify it's in the source space
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
                    // For UPDATE, we expect it might exist in target space
                    // (but we don't strictly require it)
                    // Add to apply list to overwrite
                    resourcesToApply.put(resourceId, sourceDoc);
                }
                case REMOVE -> {
                    // REMOVE: Resource has been removed from source space, exists in target
                    // Verify the resource exists in target space
                    Map<String, Object> targetDoc =
                            this.spaceService.getDocument(indexName, targetSpace, resourceId);
                    if (targetDoc != null) {
                        @SuppressWarnings("unchecked")
                        Map<String, String> targetDocSpace =
                                (Map<String, String>) targetDoc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                        String targetDocSpaceName = targetDocSpace.get(Constants.KEY_NAME);
                        if (!targetSpace.equals(targetDocSpaceName)) {
                            log.warn(
                                    "Resource '{}' to delete is in space '{}', not target space '{}'",
                                    resourceId,
                                    targetDocSpaceName,
                                    targetSpace);
                        }
                    }

                    // Mark for deletion
                    resourcesToDelete.add(resourceId);
                    log.debug(
                            "Resource '{}' marked for deletion from target space {}", resourceId, targetSpace);
                }
            }
        }
    }

    /**
     * Consolidates all changes after successful engine validation. Wraps {@link #doConsolidate} with
     * a LIFO rollback on failure.
     *
     * @param context The promotion context containing all resources to consolidate.
     * @throws IOException If consolidation fails (rollback will have been attempted already).
     */
    private void consolidateChanges(PromotionContext context) throws IOException {
        try {
            this.doConsolidate(context);
        } catch (Exception e) {
            log.error("Consolidation failed, initiating LIFO rollback: {}", e.getMessage());
            this.rollbackChanges(context);
            throw e instanceof IOException
                    ? (IOException) e
                    : new IOException("Consolidation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Promotes resources to the target space index and records a rollback step on success.
     *
     * @param resourceType The resource type key.
     * @param resources The resources to apply.
     * @param context The promotion context (for target space and rollback stack).
     * @throws IOException If the index operation fails.
     */
    private void promoteIfNotEmpty(
            String resourceType, Map<String, Map<String, Object>> resources, PromotionContext context)
            throws IOException {
        if (!resources.isEmpty()) {
            this.spaceService.promoteSpace(
                    this.spaceService.getIndexForResourceType(resourceType), resources, context.targetSpace);
            context.rollbackSteps.add(new RollbackStep(RollbackStep.Kind.APPLY, resourceType));
        }
    }

    /**
     * Deletes resources from the target space index and records a rollback step on success.
     *
     * @param resourceType The resource type key.
     * @param ids The resource IDs to delete.
     * @param context The promotion context (for target space and rollback stack).
     * @throws IOException If the index operation fails.
     */
    private void deleteIfNotEmpty(String resourceType, Set<String> ids, PromotionContext context)
            throws IOException {
        if (!ids.isEmpty()) {
            this.spaceService.deleteResources(
                    this.spaceService.getIndexForResourceType(resourceType), ids, context.targetSpace);
            context.rollbackSteps.add(new RollbackStep(RollbackStep.Kind.DELETE, resourceType));
        }
    }

    /**
     * Internal consolidation logic. Performs CM index mutations first (tracked for rollback), then
     * best-effort SAP synchronization.
     *
     * @param context The promotion context containing all resources to consolidate.
     * @throws IOException If any CM index mutation fails.
     */
    private void doConsolidate(PromotionContext context) throws IOException {
        Space targetSpaceEnum = Space.fromValue(context.targetSpace);
        ObjectMapper mapper = new ObjectMapper();

        // Consolidate ADD/UPDATE operations for each resource type
        for (String type : APPLY_RESOURCE_TYPES) {
            this.promoteIfNotEmpty(type, context.getApplyMap(type), context);
        }

        // Process DELETE operations for each resource type
        for (String type : DELETE_RESOURCE_TYPES) {
            this.deleteIfNotEmpty(type, context.getDeleteSet(type), context);
        }

        // Best-effort SAP synchronization.
        // Deletes must happen before upserts: rules before integrations (dependency order).
        for (String ruleId : context.rulesToDelete) {
            try {
                this.securityAnalyticsService.deleteRule(ruleId, targetSpaceEnum);
            } catch (Exception e) {
                log.warn(
                        "Failed to delete rule [{}] from SAP for space [{}]: {}",
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
                        "Failed to delete integration [{}] from SAP for space [{}]: {}",
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

    /**
     * Best-effort upsert of resources to the Security Analytics Plugin. Uses POST for new resources
     * (no old version) and PUT for updates.
     *
     * @param resources The resources to upsert.
     * @param oldVersionsForType The pre-promotion snapshots to determine POST vs PUT.
     * @param resourceType The resource type key.
     * @param targetSpaceEnum The target space.
     * @param mapper The ObjectMapper for JSON conversion.
     * @param targetSpace The target space name (for logging).
     */
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
                            "Failed to sync {} [{}] to SAP for space [{}]: {}",
                            resourceType,
                            entry.getKey(),
                            targetSpace,
                            e.getMessage());
                }
            }
        }
    }

    /**
     * Replays recorded {@link RollbackStep}s in strict LIFO order, undoing each Content Manager index
     * mutation. After CM rollback completes, performs a best-effort SAP reconciliation.
     *
     * @param context The promotion context with the rollback stack.
     */
    private void rollbackChanges(PromotionContext context) {
        log.info(
                "Starting LIFO rollback of promotion to space [{}] ({} steps)",
                context.targetSpace,
                context.rollbackSteps.size());

        ListIterator<RollbackStep> it =
                context.rollbackSteps.listIterator(context.rollbackSteps.size());

        while (it.hasPrevious()) {
            RollbackStep step = it.previous();
            try {
                this.rollbackCmStep(step, context);
                log.info("Rollback step OK: {}", step);
            } catch (Exception e) {
                log.error("Rollback step FAILED [{}]: {}", step, e.getMessage());
            }
        }

        log.info("LIFO rollback completed for promotion to space [{}]", context.targetSpace);
        this.reconcileSapAfterRollback(context);
    }

    /**
     * Undoes a single Content Manager index operation.
     *
     * <ul>
     *   <li>APPLY with old version = null (ADD): deletes the newly created document.
     *   <li>APPLY with old version ≠ null (UPDATE): restores the previous version.
     *   <li>DELETE: re-indexes the pre-deletion snapshot.
     * </ul>
     *
     * @param step The rollback step describing what to undo.
     * @param context The promotion context containing snapshot data.
     * @throws IOException If the CM index operation fails.
     */
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
                this.spaceService.deleteResources(indexName, toDelete, context.targetSpace);
            }
            if (!toRestore.isEmpty()) {
                this.spaceService.promoteSpace(indexName, toRestore, context.targetSpace);
            }
        } else {
            Map<String, Map<String, Object>> snapshots =
                    context.deleteSnapshots.getOrDefault(step.resourceType, Collections.emptyMap());
            if (!snapshots.isEmpty()) {
                this.spaceService.promoteSpace(indexName, snapshots, context.targetSpace);
            }
        }
    }

    /**
     * Best-effort cleanup of SAP resources synced during the forward pass. Processes in dependency
     * order: revert rules before integrations, then restore deleted resources in reverse order.
     *
     * @param context The promotion context containing SAP sync data and snapshots.
     */
    private void reconcileSapAfterRollback(PromotionContext context) {
        Space targetSpaceEnum = Space.fromValue(context.targetSpace);
        ObjectMapper mapper = new ObjectMapper();

        // 1. Revert added/updated rules (must go before integrations)
        this.revertSapApplied(
                context.rulesToApply,
                context.oldVersions.getOrDefault(Constants.KEY_RULES, Collections.emptyMap()),
                Constants.KEY_RULES,
                targetSpaceEnum,
                mapper);

        // 2. Revert added/updated integrations
        this.revertSapApplied(
                context.integrationsToApply,
                context.oldVersions.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyMap()),
                Constants.KEY_INTEGRATIONS,
                targetSpaceEnum,
                mapper);

        // 3. Restore deleted integrations
        this.restoreSapDeleted(
                context.deleteSnapshots.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyMap()),
                Constants.KEY_INTEGRATIONS,
                targetSpaceEnum,
                mapper);

        // 4. Restore deleted rules
        this.restoreSapDeleted(
                context.deleteSnapshots.getOrDefault(Constants.KEY_RULES, Collections.emptyMap()),
                Constants.KEY_RULES,
                targetSpaceEnum,
                mapper);
    }

    /**
     * Reverts SAP resources applied during the forward pass. ADDs are deleted; UPDATEs are restored
     * to their previous version.
     */
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
                    // Was a new addition → delete from SAP
                    if (Constants.KEY_INTEGRATIONS.equals(resourceType)) {
                        this.securityAnalyticsService.deleteIntegration(id, targetSpaceEnum);
                    } else {
                        this.securityAnalyticsService.deleteRule(id, targetSpaceEnum);
                    }
                    log.info(
                            "SAP reconciliation: deleted {} [{}] from space [{}]",
                            resourceType,
                            id,
                            targetSpaceEnum);
                } else if (oldVersion.containsKey(Constants.KEY_DOCUMENT)) {
                    // Was an update → restore old version
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
                    log.info(
                            "SAP reconciliation: restored {} [{}] in space [{}]",
                            resourceType,
                            id,
                            targetSpaceEnum);
                }
            } catch (Exception e) {
                log.warn("SAP reconciliation failed for {} [{}]: {}", resourceType, id, e.getMessage());
            }
        }
    }

    /**
     * Restores SAP resources that were deleted during the forward pass by re-creating them from their
     * pre-deletion snapshots.
     */
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
                    log.info(
                            "SAP reconciliation: restored deleted {} [{}] in space [{}]",
                            resourceType,
                            id,
                            targetSpaceEnum);
                }
            } catch (Exception e) {
                log.warn(
                        "SAP reconciliation failed to restore deleted {} [{}]: {}",
                        resourceType,
                        id,
                        e.getMessage());
            }
        }
    }

    /**
     * Internal context class to hold promotion data and rollback state.
     *
     * <p>Stores pre-promotion snapshots and a LIFO rollback stack. Only CM index mutations are
     * tracked; SAP reconciliation is best-effort post-rollback.
     */
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

        /** Pre-promotion snapshots keyed by resource type. null value = new addition. */
        final Map<String, Map<String, Map<String, Object>>> oldVersions = new HashMap<>();

        /** Snapshots of documents about to be deleted, keyed by resource type. */
        final Map<String, Map<String, Map<String, Object>>> deleteSnapshots = new HashMap<>();

        /** Ordered rollback stack — every successful CM mutation is pushed here. */
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

        /** Returns the apply map for the given resource type. */
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

        /** Returns the delete set for the given resource type. */
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

    /**
     * A single CM index mutation that can be undone during rollback.
     *
     * @param kind APPLY (add/update) or DELETE.
     * @param resourceType The resource type constant.
     */
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
