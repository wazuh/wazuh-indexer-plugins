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
package com.wazuh.contentmanager.rest.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.model.SpaceDiff;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/promote
 *
 * <p>Execute promotion process in the local engine. Possible HTTP responses:
 *
 * <pre>
 *  - 200 Accepted: Wazuh Engine replied with a successful response.
 *  - 400 Bad Request: Wazuh Engine replied with an error response.
 *  - 500 Internal Server Error: Unexpected error during processing. Wazuh Engine did not respond.
 * </pre>
 */
public class RestPostPromoteAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostPromoteAction.class);
    private static final String ENDPOINT_NAME = "content_manager_promote";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/promote";

    private final EngineService engine;
    private final SpaceService spaceService;

    /**
     * Constructor.
     *
     * @param engine The service instance to communicate with the local engine service.
     * @param spaceService The service instance to manage space operations.
     */
    public RestPostPromoteAction(EngineService engine, SpaceService spaceService) {
        this.engine = engine;
        this.spaceService = spaceService;
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
                        .method(POST)
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
     * Execute the space promotion operation.
     *
     * @param request incoming request
     * @return a RestResponse
     */
    public RestResponse handleRequest(RestRequest request) {
        // 1. Check if engine service exists
        if (this.engine == null) {
            return new RestResponse(
                    Constants.E_500_ENGINE_INSTANCE_IS_NULL, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // 2. Check request's payload exists
        if (request == null || !request.hasContent()) {
            return new RestResponse(
                    Constants.E_400_JSON_REQUEST_BODY_IS_REQUIRED, RestStatus.BAD_REQUEST.getStatus());
        }

        try {
            // 1. Validation Phase - Validate payload
            ObjectMapper mapper = new ObjectMapper();
            SpaceDiff spaceDiff = mapper.readValue(request.content().streamInput(), SpaceDiff.class);
            this.validatePromoteRequest(spaceDiff);

            // 2. Gathering Phase - Build the engine payload
            PromotionContext context = this.gatherPromotionData(spaceDiff);

            // 3. Validation Phase - Invoke engine validation
            RestResponse engineResponse = this.engine.promote(context.enginePayload);

            // Check if engine validation was successful
            if (engineResponse.getStatus() != RestStatus.OK.getStatus()
                    && engineResponse.getStatus() != RestStatus.ACCEPTED.getStatus()) {
                log.warn("Engine validation failed: {}", engineResponse.getMessage());
                return engineResponse;
            }

            // 4. Consolidation Phase - Apply changes to target space
            this.consolidateChanges(context);

            // 5. Response Phase - Reply with success
            return new RestResponse(Constants.S_200_PROMOTION_COMPLETED, RestStatus.OK.getStatus());
        } catch (IllegalArgumentException e) {
            log.warn("Validation error during promotion: {}", e.getMessage());
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (com.fasterxml.jackson.databind.exc.ValueInstantiationException e) {
            log.warn("Invalid value in request: {}", e.getMessage());
            // Extract the root cause message for better error reporting
            String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
            return new RestResponse(message, RestStatus.BAD_REQUEST.getStatus());
        } catch (IndexNotFoundException e) {
            log.error("Index not found during promotion: {}", e.getMessage(), e);
            return new RestResponse(e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        } catch (IOException e) {
            log.error("IO error during promotion: {}", e.getMessage(), e);
            String message =
                    e.getMessage() != null ? e.getMessage() : "An IO error occurred during promotion";
            return new RestResponse(message, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        } catch (Exception e) {
            log.error("Unexpected error during promotion: {}", e.getMessage(), e);
            String message =
                    e.getMessage() != null ? e.getMessage() : "An unexpected error occurred during promotion";
            return new RestResponse(message, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
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
                || changes.getFilters() == null) {
            throw new IllegalArgumentException(
                    "All resource type lists (policy, integrations, kvdbs, decoders, filters) are required in changes");
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
     * the target space and applies the modifications from the source space.
     *
     * @param spaceDiff The space diff request.
     * @return A PromotionContext containing the engine payload and consolidation data.
     * @throws IOException If any data gathering fails.
     */
    private PromotionContext gatherPromotionData(SpaceDiff spaceDiff) throws IOException {
        Space sourceSpace = spaceDiff.getSpace();
        Space targetSpace = sourceSpace.promote();
        SpaceDiff.Changes changes = spaceDiff.getChanges();

        // Fetch the target policy
        Map<String, Object> policyDocument = this.spaceService.getPolicy(targetSpace.toString());
        if (policyDocument == null) {
            throw new IOException("Policy document not found for target space: " + targetSpace);
        }

        // Maps to track resources to apply (ADD/UPDATE) - from source space
        Map<String, Map<String, Object>> policyToApply = new HashMap<>();
        Map<String, Map<String, Object>> integrationsToApply = new HashMap<>();
        Map<String, Map<String, Object>> kvdbsToApply = new HashMap<>();
        Map<String, Map<String, Object>> decodersToApply = new HashMap<>();
        Map<String, Map<String, Object>> filtersToApply = new HashMap<>();
        // TODO promotion of rules

        // Sets to track resources to delete
        Set<String> integrationsToDelete = new HashSet<>();
        Set<String> kvdbsToDelete = new HashSet<>();
        Set<String> decodersToDelete = new HashSet<>();
        Set<String> filtersToDelete = new HashSet<>();

        // Process each resource type
        this.processResourceChanges(
                changes.getPolicy(),
                Constants.KEY_POLICIES,
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

        return new PromotionContext(
                enginePayload,
                integrationsToApply,
                kvdbsToApply,
                decodersToApply,
                filtersToApply,
                integrationsToDelete,
                kvdbsToDelete,
                decodersToDelete,
                filtersToDelete,
                targetSpace.toString());
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
                    Map<String, Object> sourceDoc = this.spaceService.getDocument(indexName, resourceId);
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
                            (Map<String, String>) sourceDoc.getOrDefault("space", new HashMap<>());
                    String docSpace = sourceDocSpace.get("name");
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
                    // We check all docs with same ID regardless of space
                    Map<String, Object> targetDoc = this.spaceService.getDocument(indexName, resourceId);
                    if (targetDoc != null) {
                        @SuppressWarnings("unchecked")
                        Map<String, String> targetDocSpace =
                                (Map<String, String>) targetDoc.getOrDefault("space", new HashMap<>());
                        String targetDocSpaceName = targetDocSpace.get("name");
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
                    // UPDATE: Resource exists in BOTH source and target spaces
                    Map<String, Object> sourceDoc = this.spaceService.getDocument(indexName, resourceId);
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
                            (Map<String, String>) sourceDoc.getOrDefault("space", new HashMap<>());
                    String docSpace = sourceDocSpace.get("name");
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
                case DELETE -> {
                    // DELETE: Resource has been removed from source space, exists in target
                    // Verify the resource exists in target space
                    Map<String, Object> targetDoc = this.spaceService.getDocument(indexName, resourceId);
                    if (targetDoc != null) {
                        @SuppressWarnings("unchecked")
                        Map<String, String> targetDocSpace =
                                (Map<String, String>) targetDoc.getOrDefault("space", new HashMap<>());
                        String targetDocSpaceName = targetDocSpace.get("name");
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
     * Consolidates all changes after successful validation by applying ADD/UPDATE operations and
     * DELETE operations.
     *
     * @param context The promotion context containing all resources to consolidate.
     * @throws IOException If consolidation fails.
     */
    private void consolidateChanges(PromotionContext context) throws IOException {
        // Consolidate ADD/UPDATE operations for each resource type
        if (!context.integrationsToApply.isEmpty()) {
            this.spaceService.promoteSpace(
                    this.spaceService.getIndexForResourceType(Constants.KEY_INTEGRATIONS),
                    context.integrationsToApply,
                    context.targetSpace);
        }

        if (!context.kvdbsToApply.isEmpty()) {
            this.spaceService.promoteSpace(
                    this.spaceService.getIndexForResourceType(Constants.KEY_KVDBS),
                    context.kvdbsToApply,
                    context.targetSpace);
        }

        if (!context.decodersToApply.isEmpty()) {
            this.spaceService.promoteSpace(
                    this.spaceService.getIndexForResourceType(Constants.KEY_DECODERS),
                    context.decodersToApply,
                    context.targetSpace);
        }

        if (!context.filtersToApply.isEmpty()) {
            this.spaceService.promoteSpace(
                    this.spaceService.getIndexForResourceType(Constants.KEY_FILTERS),
                    context.filtersToApply,
                    context.targetSpace);
        }

        // Process DELETE operations for each resource type
        if (!context.integrationsToDelete.isEmpty()) {
            this.spaceService.deleteResources(
                    this.spaceService.getIndexForResourceType(Constants.KEY_INTEGRATIONS),
                    context.integrationsToDelete,
                    context.targetSpace);
        }

        if (!context.kvdbsToDelete.isEmpty()) {
            this.spaceService.deleteResources(
                    this.spaceService.getIndexForResourceType(Constants.KEY_KVDBS),
                    context.kvdbsToDelete,
                    context.targetSpace);
        }

        if (!context.decodersToDelete.isEmpty()) {
            this.spaceService.deleteResources(
                    this.spaceService.getIndexForResourceType(Constants.KEY_DECODERS),
                    context.decodersToDelete,
                    context.targetSpace);
        }

        if (!context.filtersToDelete.isEmpty()) {
            this.spaceService.deleteResources(
                    this.spaceService.getIndexForResourceType(Constants.KEY_FILTERS),
                    context.filtersToDelete,
                    context.targetSpace);
        }
    }

    /** Internal context class to hold promotion data. */
    private static class PromotionContext {
        final JsonNode enginePayload;
        final Map<String, Map<String, Object>> integrationsToApply;
        final Map<String, Map<String, Object>> kvdbsToApply;
        final Map<String, Map<String, Object>> decodersToApply;
        final Map<String, Map<String, Object>> filtersToApply;
        final Set<String> integrationsToDelete;
        final Set<String> kvdbsToDelete;
        final Set<String> decodersToDelete;
        final Set<String> filtersToDelete;
        final String targetSpace;

        PromotionContext(
                JsonNode enginePayload,
                Map<String, Map<String, Object>> integrationsToApply,
                Map<String, Map<String, Object>> kvdbsToApply,
                Map<String, Map<String, Object>> decodersToApply,
                Map<String, Map<String, Object>> filtersToApply,
                Set<String> integrationsToDelete,
                Set<String> kvdbsToDelete,
                Set<String> decodersToDelete,
                Set<String> filtersToDelete,
                String targetSpace) {
            this.enginePayload = enginePayload;
            this.integrationsToApply = integrationsToApply;
            this.kvdbsToApply = kvdbsToApply;
            this.decodersToApply = decodersToApply;
            this.filtersToApply = filtersToApply;
            this.integrationsToDelete = integrationsToDelete;
            this.kvdbsToDelete = kvdbsToDelete;
            this.decodersToDelete = decodersToDelete;
            this.filtersToDelete = filtersToDelete;
            this.targetSpace = targetSpace;
        }
    }
}
