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

import com.google.gson.JsonArray;
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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.engine.services.EngineService;
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
    private static final String DECODERS_INDEX = ".cti-decoders";
    private static final String SPACE_NAME_FIELD = "space.name";
    private static final String ID_FIELD = "id";

    private final EngineService engine;
    private NodeClient client;
    private PolicyHashService policyHashService;

    /**
     * Constructs a new RestPutPolicyAction handler.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPutPolicyAction(EngineService engine) {
        this.engine = engine;
    }

    /**
     * Constructs a new RestPutPolicyAction handler with explicit NodeClient (for testing or DI).
     *
     * @param engine The service instance to communicate with the local engine service.
     * @param client The NodeClient to use for index operations.
     */
    public RestPutPolicyAction(EngineService engine, NodeClient client) {
        this.engine = engine;
        this.client = client;
    }

    /**
     * Setter for the policy hash service, used in tests.
     *
     * @param policyHashService the policy hash service to set
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
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
     * @param client the node client for index operations
     * @return a consumer that executes the policy update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        this.client = client;
        this.policyHashService = new PolicyHashService(client);
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
     * </ol>
     *
     * @param request incoming REST request containing the policy data
     * @return a RestResponse describing the outcome of the operation
     */
    public RestResponse handleRequest(RestRequest request) {
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
        // Validate document type is "policy"
        if (!policy.getType().toLowerCase(Locale.ROOT).equals("policy")) {
            return new RestResponse(
                    "Invalid document type: " + policy.getType(), RestStatus.BAD_REQUEST.getStatus());
        }
        // Store or update the policy
        try {
            String policyId = this.storePolicy(policy);

            // Regenerate space hash because policy content changed
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(
                    "Updated draft policy with ID " + policyId, RestStatus.OK.getStatus());
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
     * <p>The request is expected to have the following structure:
     *
     * <pre>
     * {
     *   "type": "policy",
     *   "resource": {
     *     "root_decoder": "...",
     *     "integrations": [...],
     *     "author": "...",
     *     "description": "...",
     *     "documentation": "...",
     *     "references": [...],
     *     "title": "..."
     *   }
     * }
     * </pre>
     *
     * @param request the REST request containing the policy JSON
     * @return the parsed Policy object
     * @throws IOException if parsing fails
     */
    private Policy parsePolicy(RestRequest request) throws IOException {
        ObjectMapper mapper = new ObjectMapper();

        // Parse the request as a generic map to handle nested structure
        @SuppressWarnings("unchecked")
        Map<String, Object> requestBody = mapper.readValue(request.content().utf8ToString(), Map.class);

        // Extract the type from the top level
        String type = (String) requestBody.get("type");

        // Extract the resource object
        @SuppressWarnings("unchecked")
        Map<String, Object> resource = (Map<String, Object>) requestBody.get("resource");

        if (resource == null) {
            throw new IOException("Missing 'resource' field in request body");
        }

        // Create a flat map with all fields for Policy deserialization
        Map<String, Object> flattenedPolicy = new HashMap<>();
        flattenedPolicy.put("type", type);
        flattenedPolicy.putAll(resource);

        // Convert back to JSON and deserialize into Policy object
        String flattenedJson = mapper.writeValueAsString(flattenedPolicy);
        return mapper.readValue(flattenedJson, Policy.class);
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
        fieldsToValidate.put("getTitle", "resource.title");
        fieldsToValidate.put("getRootDecoder", "resource.root_decoder");
        fieldsToValidate.put("getIntegrations", "resource.integrations");
        fieldsToValidate.put("getAuthor", "resource.author");
        fieldsToValidate.put("getDescription", "resource.description");
        fieldsToValidate.put("getDocumentation", "resource.documentation");
        fieldsToValidate.put("getReferences", "resource.references");
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
            } catch (IllegalAccessException
                    | NoSuchMethodException
                    | SecurityException
                    | InvocationTargetException e) {
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
     * @param policy the policy to store
     * @throws IOException if storage fails
     */
    private String storePolicy(Policy policy) throws IOException {
        ContentIndex contentIndex = new ContentIndex(this.client, POLICIES_INDEX, null);
        JsonObject policyJson = this.findDraftPolicy(contentIndex);
        JsonObject policyAsJson = policy.toJson();
        JsonObject payload = new JsonObject();
        String currentDate = Instant.now().toString();
        String policyId;

        // Create document without type field
        JsonObject document = new JsonObject();
        policyAsJson
                .entrySet()
                .forEach(
                        entry -> {
                            if (!"type".equals(entry.getKey())) {
                                document.add(entry.getKey(), entry.getValue());
                            }
                        });

        // Add timestamps to document
        document.addProperty("modified", currentDate);
        if (policyJson != null && policyJson.has(ID_FIELD)) {
            policyId = policyJson.get(ID_FIELD).getAsString();
            JsonObject existingDoc = policyJson.getAsJsonObject("document");
            if (existingDoc != null && existingDoc.has("date")) {
                document.addProperty("date", existingDoc.get("date").getAsString());
            } else {
                document.addProperty("date", currentDate);
            }
        } else {
            policyId = UUIDs.base64UUID();
            document.addProperty("date", currentDate);
        }
        // Add document to payload
        payload.add("document", document);
        // Set the Space name to DRAFT
        JsonObject spaceObject = new JsonObject();
        spaceObject.addProperty("name", Space.DRAFT.toString());
        // Generate and set the Space Hash. TODO: Implement real hash calculation
        JsonObject spaceHashObject = new JsonObject();
        spaceHashObject.addProperty("sha256", "dummy_space_hash_value");
        spaceObject.add("hash", spaceHashObject);
        // Save space property
        payload.add("space", spaceObject);

        // Store the new draft policy
        contentIndex.create(policyId, payload);
        log.info("Policy stored successfully with ID: {}", policyId);
        return policyId;
    }

    /**
     * Finds the ID of the existing draft policy, or generates a new one.
     *
     * @param contentIndex the content index to search
     * @return the existing policy ID or a new UUID
     */
    private JsonObject findDraftPolicy(ContentIndex contentIndex) {
        QueryBuilder queryBuilder = QueryBuilders.termQuery(SPACE_NAME_FIELD, Space.DRAFT.toString());
        JsonObject result = contentIndex.searchByQuery(queryBuilder);

        // searchByQuery returns { "hits": [...], "total": N }
        if (result != null && result.has("hits")) {
            JsonArray hits = result.getAsJsonArray("hits");
            if (!hits.isEmpty()) {
                JsonObject firstHit = hits.get(0).getAsJsonObject();
                if (firstHit.has(ID_FIELD)) {
                    return firstHit;
                }
            }
        }
        return null;
    }
}
