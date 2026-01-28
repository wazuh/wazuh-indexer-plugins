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

import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.UUIDs;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.Policy;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * REST handler for updating policy resources on the Wazuh Engine.
 *
 * <p>This endpoint handles PUT requests to update policy configurations in the draft space. The
 * policy defines the root decoder and integrations list for content processing.
 */
public class RestPutPolicyAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutPolicyAction.class);
    private static final String ENDPOINT_NAME = "content_manager_policy_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/policy_update";

    // Index and field constants
    private static final String POLICIES_INDEX = ".cti-policies";
    private static final String SPACE_FIELD = "space";
    private static final String ID_FIELD = "id";

    private final EngineService engine;

    /**
     * Constructs a new RestPutPolicyAction handler.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPutPolicyAction(EngineService engine) {
        this.engine = engine;
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
                        .path(PluginSettings.POLICY_URI)
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the request by returning a consumer that executes the policy update operation.
     *
     * @param request the incoming REST request containing the policy payload
     * @param client the node client (unused)
     * @return a consumer that executes the policy update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        RestResponse response = this.handleRequest(request, client);
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
     * </ol>
     *
     * @param request incoming REST request containing the policy data
     * @param client the node client
     * @return a RestResponse describing the outcome of the operation
     */
    public RestResponse handleRequest(RestRequest request, NodeClient client) {
        // Validate prerequisites
        RestResponse validationError = this.validateRequest(request);
        if (validationError != null) {
            return validationError;
        }

        // Parse policy from request
        Policy policy;
        try {
            policy = this.parsePolicy(request);
        } catch (IOException e) {
            return new RestResponse(
                    "Invalid Policy JSON content: " + request.content().utf8ToString(),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Validate policy fields
        RestResponse policyValidationError = this.validatePolicy(policy);
        if (policyValidationError != null) {
            return policyValidationError;
        }

        // Store or update the policy
        try {
            this.storePolicy(client, policy);
            return new RestResponse(policy.toString(), RestStatus.OK.getStatus());
        } catch (IOException e) {
            return new RestResponse(
                    "Failed to store the updated policy: " + e.getMessage(),
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Validates the incoming request for required conditions.
     *
     * @param request the REST request to validate
     * @return a RestResponse with error details if validation fails, null otherwise
     */
    private RestResponse validateRequest(RestRequest request) {
        if (this.engine == null) {
            return new RestResponse(
                    "Engine instance is null.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (!request.hasContent()) {
            return new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        return null;
    }

    /**
     * Parses a Policy object from the request content.
     *
     * @param request the REST request containing the policy JSON
     * @return the parsed Policy object
     * @throws IOException if parsing fails
     */
    private Policy parsePolicy(RestRequest request) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(request.content().utf8ToString(), Policy.class);
    }

    /**
     * Validates that the policy fields meet the required constraints.
     *
     * <p>Uses a dynamic reflection-based approach to validate all policy fields. Fields must not be
     * null, but can be empty strings or empty arrays. This ensures the policy structure is valid
     * before storage.
     *
     * @param policy the policy to validate
     * @return a RestResponse with error details if validation fails, null otherwise
     */
    private RestResponse validatePolicy(Policy policy) {
        // Define fields to validate with their display names
        Map<String, String> fieldsToValidate = new LinkedHashMap<>();
        fieldsToValidate.put("getType", "type");
        fieldsToValidate.put("getRootDecoder", "root_decoder");
        fieldsToValidate.put("getIntegrations", "integrations");
        fieldsToValidate.put("getAuthor", "author");
        fieldsToValidate.put("getDescription", "description");
        fieldsToValidate.put("getDocumentation", "documentation");
        fieldsToValidate.put("getReferences", "references");
        // Collect all null fields
        List<String> nullFields = new ArrayList<>();
        // Validate each field dynamically
        for (Map.Entry<String, String> entry : fieldsToValidate.entrySet()) {
            String methodName = entry.getKey();
            String fieldName = entry.getValue();
            try {
                Method getter = Policy.class.getMethod(methodName);
                Object value = getter.invoke(policy);
                if (value == null) {
                    nullFields.add(fieldName);
                }
            } catch (Exception e) {
                log.error("Error validating field '{}': {}", fieldName, e.getMessage());
                return new RestResponse(
                        "Internal validation error for field: " + fieldName,
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }
        }
        // If there are null fields, return error with all missing fields listed
        if (!nullFields.isEmpty()) {
            return new RestResponse(
                    "Invalid request body, missing fields: " + nullFields,
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Stores or updates the policy in the draft space.
     *
     * <p>If a draft policy already exists, it will be updated using its existing ID. Otherwise, a new
     * policy will be created with a generated UUID.
     *
     * @param client the node client for index operations
     * @param policy the policy to store
     * @throws IOException if storage fails
     */
    private void storePolicy(NodeClient client, Policy policy) throws IOException {
        ContentIndex contentIndex = new ContentIndex(client, POLICIES_INDEX, null);
        String policyId = this.findDraftPolicyId(contentIndex);
        contentIndex.create(policyId, policy.toJson(), Space.DRAFT.toString());
        log.info("Policy stored successfully with ID: {}", policyId);
    }

    /**
     * Finds the ID of the existing draft policy, or generates a new one.
     *
     * @param contentIndex the content index to search
     * @return the existing policy ID or a new UUID
     */
    private String findDraftPolicyId(ContentIndex contentIndex) {
        QueryBuilder queryBuilder = QueryBuilders.termQuery(SPACE_FIELD, Space.DRAFT.toString());
        JsonObject resource = contentIndex.searchByQuery(queryBuilder);

        if (resource != null && resource.has(ID_FIELD)) {
            String existingId = resource.get(ID_FIELD).getAsString();
            log.debug("Found existing draft policy with ID: {}", existingId);
            return existingId;
        }

        String newId = UUIDs.base64UUID();
        log.debug("No existing draft policy found, generated new ID: {}", newId);
        return newId;
    }
}
