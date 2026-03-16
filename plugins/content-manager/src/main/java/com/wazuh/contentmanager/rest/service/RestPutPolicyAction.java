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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * REST handler for updating policy resources on the Wazuh Engine.
 *
 * <p>This endpoint handles PUT requests to update policy configurations in the draft or standard
 * space. The policy defines the root decoder and integrations list for content processing.
 */
public class RestPutPolicyAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutPolicyAction.class);
    private static final String ENDPOINT_NAME = "content_manager_policy_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/policy_update";

    private SpaceService spaceService;
    private NodeClient client;
    private PayloadValidations payloadValidations;

    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Constructs a new RestPutPolicyAction handler.
     *
     * @param spaceService The space service instance to fetch policies.
     */
    public RestPutPolicyAction(SpaceService spaceService) {
        this.spaceService = spaceService;
        this.payloadValidations = new PayloadValidations();
    }

    /**
     * Constructs a new RestPutPolicyAction handler with explicit NodeClient (for testing or DI).
     *
     * @param spaceService The space service instance to fetch policies.
     * @param client The NodeClient to use for index operations. TODO should not be required to pass
     *     the client
     */
    public RestPutPolicyAction(SpaceService spaceService, NodeClient client) {
        this.spaceService = spaceService;
        this.client = client;
        this.payloadValidations = new PayloadValidations();
    }

    /**
     * Setter for the policy hash service, used in tests.
     *
     * @param spaceService the policy hash service to set
     */
    public void setPolicyHashService(SpaceService spaceService) {
        this.spaceService = spaceService;
    }

    /**
     * Setter for the payload validations, used in tests.
     *
     * @param payloadValidations the payload validations instance to set
     */
    public void setPayloadValidations(PayloadValidations payloadValidations) {
        this.payloadValidations = payloadValidations;
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
                        .path(PluginSettings.POLICY_URI + "/{space}")
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the request by returning a consumer that executes the policy update operation.
     *
     * @param request the incoming REST request containing the policy payload
     * @param client the node client for index operations
     * @return a consumer that executes the policy update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        this.client = client;
        this.spaceService = new SpaceService(client);
        RestResponse response = this.handleRequest(request);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    /**
     * Handles the policy update request by validating the payload and storing the policy.
     *
     * <p>This method performs the following validations:
     *
     * <ol>
     *   <li>Checks that the engine service is available
     *   <li>Verifies that the request contains a JSON payload
     *   <li>Parses and validates the Policy JSON structure
     *   <li>Validates the space path parameter
     * </ol>
     *
     * @param request incoming REST request containing the policy data
     * @return a RestResponse describing the outcome of the operation
     */
    public RestResponse handleRequest(RestRequest request) {
        // 1. Check request's payload exists
        if (request == null || !request.hasContent()) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }
        try {
            // Extract and validate space parameter
            String spaceName = request.param(Constants.KEY_SPACE);
            if (!Space.DRAFT.equals(spaceName) && !Space.STANDARD.equals(spaceName)) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT,
                                Constants.E_400_RESOURCE_SPACE_MISMATCH,
                                Space.DRAFT + ", " + Space.STANDARD),
                        RestStatus.BAD_REQUEST.getStatus());
            }

            // 2. Validate request content
            JsonNode jsonContent;
            try {
                jsonContent = mapper.readTree(request.content().utf8ToString());
            } catch (IOException e) {
                return new RestResponse(
                        Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
            }

            // Validate "resource"
            if (!jsonContent.has(Constants.KEY_RESOURCE)) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_RESOURCE),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            JsonNode resource = jsonContent.get(Constants.KEY_RESOURCE);
            log.debug(Constants.D_LOG_OPERATION, "Updating", Constants.KEY_POLICY, resource);
            Policy policy;
            try {
                policy = mapper.readValue(resource.toString(), Policy.class);
            } catch (IOException e) {
                return new RestResponse(
                        Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
            }

            // Validate required Policy fields
            List<String> missingFields = new ArrayList<>();
            if (policy.getEnabled() == null) {
                missingFields.add(Constants.KEY_ENABLED);
            }
            if (policy.getIndexUnclassifiedEvents() == null) {
                missingFields.add("index_unclassified_events");
            }
            if (policy.getIndexDiscardedEvents() == null) {
                missingFields.add("index_discarded_events");
            }

            // Draft space requires additional fields
            if (Space.DRAFT.equals(spaceName)) {
                if (policy.getAuthor() == null || policy.getAuthor().isEmpty()) {
                    missingFields.add(Constants.KEY_AUTHOR);
                }
                if (policy.getDescription() == null || policy.getDescription().isEmpty()) {
                    missingFields.add(Constants.KEY_DESCRIPTION);
                }
                if (policy.getDocumentation() == null) {
                    missingFields.add("documentation");
                }
                if (policy.getReferences() == null) {
                    missingFields.add("references");
                }
            }

            if (!missingFields.isEmpty()) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_MISSING_FIELD, String.join(", ", missingFields)),
                        RestStatus.BAD_REQUEST.getStatus());
            }

            Set<String> knownEnrichmentTypes = this.spaceService.getKnownEnrichmentTypes();

            // Validate enrichments: only allowed values, no duplicates
            RestResponse enrichmentsValidationError =
                    this.payloadValidations.validateEnrichments(
                            policy.getEnrichments(), knownEnrichmentTypes);
            if (enrichmentsValidationError != null) {
                return enrichmentsValidationError;
            }

            // 3. Update policy based on target space
            String policyId;
            if (Space.STANDARD.equals(spaceName)) {
                policyId = this.updateStandardPolicy(policy);
            } else {
                policyId = this.updatePolicy(policy);
            }

            // Regenerate space hash because space composition changed
            this.spaceService.calculateAndUpdate(List.of(spaceName));

            return new RestResponse(policyId, RestStatus.OK.getStatus());
        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY + " " + e.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            log.error(
                    Constants.E_LOG_OPERATION_FAILED, "updating", Constants.KEY_POLICY, e.getMessage(), e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR + " " + e.getMessage(),
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Stores or updates the policy in the standard space.
     *
     * <p>Only the following fields from the incoming policy are applied: enrichments, filters,
     * enabled, index_unclassified_events, and index_discarded_events. All other fields are preserved
     * from the existing standard policy document.
     *
     * @param incomingPolicy the incoming policy containing the fields to update
     * @return the document ID of the persisted policy
     * @throws IOException if storage fails
     * @throws IllegalStateException if the standard policy document is not found
     */
    @SuppressWarnings("unchecked")
    private String updateStandardPolicy(Policy incomingPolicy)
            throws IOException, IllegalStateException {
        // Get current standard policy
        Map<String, Object> currentPolicy = this.spaceService.getPolicy(Space.STANDARD.toString());
        Map<String, Object> currentPolicyDoc =
                (Map<String, Object>) currentPolicy.get(Constants.KEY_DOCUMENT);
        if (currentPolicyDoc == null) {
            throw new IllegalStateException(
                    Constants.E_500_INTERNAL_SERVER_ERROR + " Policy document not found in standard space.");
        }

        // Validate filters: allow reordering but prevent addition/removal
        List<String> currentFilters =
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_FILTERS, Collections.emptyList());
        List<String> newFilters = incomingPolicy.getFilters();

        RestResponse filtersValidationError =
                this.payloadValidations.validateListEquality(
                        currentFilters, newFilters, Constants.KEY_FILTERS);
        if (filtersValidationError != null) {
            throw new IllegalArgumentException(filtersValidationError.getMessage());
        }

        // Safekeep all unmodifiable values from the existing standard policy
        String docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();

        // Extract metadata from existing policy (now nested under "metadata", fallback to root)
        @SuppressWarnings("unchecked")
        Map<String, Object> existingMetadata =
                (Map<String, Object>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_METADATA, Collections.emptyMap());

        Object dateObj = existingMetadata.get(Constants.KEY_DATE);
        if (dateObj == null) dateObj = currentPolicyDoc.get(Constants.KEY_DATE);
        String docCreationDate = dateObj != null ? dateObj.toString() : "";

        // Build a policy preserving existing fields, only overriding the 5 allowed fields
        Policy mergedPolicy = new Policy();
        mergedPolicy.setId(docId);
        mergedPolicy.setDate(docCreationDate);
        mergedPolicy.setModified(Instant.now().toString());

        Object titleObj = existingMetadata.get(Constants.KEY_TITLE);
        if (titleObj == null) titleObj = currentPolicyDoc.get(Constants.KEY_TITLE);
        mergedPolicy.setTitle(titleObj != null ? titleObj.toString() : "");

        Object authorObj = existingMetadata.get(Constants.KEY_AUTHOR);
        if (authorObj == null) authorObj = currentPolicyDoc.get(Constants.KEY_AUTHOR);
        mergedPolicy.setAuthor(authorObj != null ? authorObj.toString() : "");

        Object descObj = existingMetadata.get(Constants.KEY_DESCRIPTION);
        if (descObj == null) descObj = currentPolicyDoc.get(Constants.KEY_DESCRIPTION);
        mergedPolicy.setDescription(descObj != null ? descObj.toString() : "");

        Object docObj = existingMetadata.get("documentation");
        if (docObj == null) docObj = currentPolicyDoc.get("documentation");
        mergedPolicy.setDocumentation(docObj != null ? docObj.toString() : "");

        Object refObj = existingMetadata.get("references");
        if (refObj == null) refObj = currentPolicyDoc.get("references");
        @SuppressWarnings("unchecked")
        List<String> existingReferences =
                (List<String>) (refObj != null ? refObj : Collections.emptyList());
        mergedPolicy.setReferences(existingReferences);

        mergedPolicy.setRootDecoder((String) currentPolicyDoc.getOrDefault("root_decoder", ""));
        mergedPolicy.setIntegrations(
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyList()));

        // Apply the 5 modifiable fields from the incoming payload
        mergedPolicy.setEnrichments(incomingPolicy.getEnrichments());
        mergedPolicy.setFilters(incomingPolicy.getFilters());
        mergedPolicy.setEnabled(incomingPolicy.getEnabled());
        mergedPolicy.setIndexUnclassifiedEvents(incomingPolicy.getIndexUnclassifiedEvents());
        mergedPolicy.setIndexDiscardedEvents(incomingPolicy.getIndexDiscardedEvents());

        // Convert to JsonNode and persist
        JsonNode policyNode = mapper.valueToTree(mergedPolicy);

        ContentIndex index = new ContentIndex(this.client, Constants.INDEX_POLICIES, null);
        try {
            ObjectNode document = mapper.createObjectNode();
            document.set(Constants.KEY_DOCUMENT, policyNode);
            ObjectNode spaceNode = mapper.createObjectNode();
            spaceNode.put(Constants.KEY_NAME, Space.STANDARD.toString());
            document.set(Constants.KEY_SPACE, spaceNode);
            String hash = Resource.computeSha256(policyNode.toString());
            ObjectNode hashNode = mapper.createObjectNode();
            hashNode.put(Constants.KEY_SHA256, hash);
            document.set(Constants.KEY_HASH, hashNode);
            String standardPolicyId =
                    this.spaceService.findDocumentId(
                            Constants.INDEX_POLICIES, Space.STANDARD.toString(), docId);
            IndexResponse indexResponse = index.create(standardPolicyId, document);
            return indexResponse.getId();
        } catch (Exception e) {
            throw new IllegalStateException("Standard policy not found: " + e.getMessage());
        }
    }

    /**
     * Stores or updates the policy in the draft space.
     *
     * <p>If a draft policy already exists, it will be updated using its existing ID. Otherwise, a new
     * policy will be created with a generated UUID.
     *
     * @param policy the policy to store
     * @throws IOException if storage fails
     */
    @SuppressWarnings("unchecked")
    private String updatePolicy(Policy policy) throws IOException, IllegalStateException {
        // Get policy in the draft space
        Map<String, Object> currentPolicy = this.spaceService.getPolicy(Space.DRAFT.toString());

        // Safekeep unmodifiable values
        Map<String, Object> currentPolicyDoc =
                (Map<String, Object>) currentPolicy.get(Constants.KEY_DOCUMENT);
        if (currentPolicyDoc == null) {
            throw new IllegalStateException(
                    Constants.E_500_INTERNAL_SERVER_ERROR + " Policy document not found in draft space.");
        }

        // Validate integrations: allow reordering but prevent addition/removal
        List<String> currentIntegrations =
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyList());
        List<String> newIntegrations = policy.getIntegrations();

        // Validation for integrations array: allow reordering but prevent addition/removal
        RestResponse validationError =
                this.payloadValidations.validateListEquality(
                        currentIntegrations, newIntegrations, Constants.KEY_INTEGRATIONS);
        if (validationError != null) {
            throw new IllegalArgumentException(validationError.getMessage());
        }

        // Validation for filters array: allow reordering but prevent addition/removal
        List<String> currentFilters =
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_FILTERS, Collections.emptyList());
        List<String> newFilters = policy.getFilters();

        RestResponse filtersValidationError =
                this.payloadValidations.validateListEquality(
                        currentFilters, newFilters, Constants.KEY_FILTERS);
        if (filtersValidationError != null) {
            throw new IllegalArgumentException(filtersValidationError.getMessage());
        }

        String docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();
        @SuppressWarnings("unchecked")
        Map<String, Object> existingMeta =
                (Map<String, Object>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_METADATA, Collections.emptyMap());

        Object dateObj = existingMeta.get(Constants.KEY_DATE);
        if (dateObj == null) dateObj = currentPolicyDoc.get(Constants.KEY_DATE);
        String docCreationDate = dateObj != null ? dateObj.toString() : "";
        String docModificationDate = Instant.now().toString();

        // Update (set or overwrite unmodifiable values in incoming policy document)
        policy.setId(docId);
        policy.setDate(docCreationDate);
        policy.setModified(docModificationDate);

        // Convert Policy to JsonNode
        JsonNode policyNode = mapper.valueToTree(policy);

        ContentIndex index = new ContentIndex(this.client, Constants.INDEX_POLICIES, null);
        try {
            // Build CTI wrapper with automatic hash calculation
            ObjectNode document = mapper.createObjectNode();
            document.set(Constants.KEY_DOCUMENT, policyNode);
            ObjectNode spaceNode = mapper.createObjectNode();
            spaceNode.put(Constants.KEY_NAME, Space.DRAFT.toString());
            document.set(Constants.KEY_SPACE, spaceNode);
            String hash = Resource.computeSha256(policyNode.toString());
            ObjectNode hashNode = mapper.createObjectNode();
            hashNode.put(Constants.KEY_SHA256, hash);
            document.set(Constants.KEY_HASH, hashNode);
            String draftPolicyId =
                    this.spaceService.findDocumentId(Constants.INDEX_POLICIES, Space.DRAFT.toString(), docId);
            IndexResponse indexResponse = index.create(draftPolicyId, document);
            return indexResponse.getId();
        } catch (Exception e) {
            throw new IllegalStateException("Draft policy not found: " + e.getMessage());
        }
    }
}
