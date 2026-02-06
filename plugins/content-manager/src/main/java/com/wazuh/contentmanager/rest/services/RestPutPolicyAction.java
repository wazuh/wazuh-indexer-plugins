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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

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

    private final SpaceService spaceService;
    private NodeClient client;
    private PolicyHashService policyHashService;

    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Constructs a new RestPutPolicyAction handler.
     *
     * @param spaceService The space service instance to fetch policies.
     */
    public RestPutPolicyAction(SpaceService spaceService) {
        this.spaceService = spaceService;
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
        // 1. Check request's payload exists
        if (request == null || !request.hasContent()) {
            return new RestResponse(
                    Constants.E_400_JSON_REQUEST_BODY_IS_REQUIRED, RestStatus.BAD_REQUEST.getStatus());
        }
        try {
            // 2. Validate request content
            JsonNode jsonContent = mapper.readTree(request.content().utf8ToString());

            // Validate "type"
            if (!jsonContent.has(Constants.KEY_TYPE)) {
                throw new IllegalArgumentException(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_TYPE));
            }
            String resourceType = jsonContent.get(Constants.KEY_TYPE).asText();
            if (resourceType.isBlank() && !resourceType.equals(Constants.KEY_TYPE)) {
                throw new IllegalArgumentException(
                        String.format(
                                Locale.ROOT,
                                "Invalid '%s' field. Expected '%s'.",
                                Constants.KEY_TYPE,
                                Constants.KEY_POLICY));
            }

            // Validate "resource"
            if (!jsonContent.has(Constants.KEY_RESOURCE)) {
                throw new IllegalArgumentException(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_RESOURCE));
            }
            JsonNode resource = jsonContent.get(Constants.KEY_RESOURCE);
            log.info(resource.toString());
            Policy policy = mapper.readValue(resource.toString(), Policy.class);

            // Validate required Policy fields
            List<String> missingFields = new ArrayList<>();
            if (policy.getAuthor() == null || policy.getAuthor().isEmpty()) {
                missingFields.add(Constants.KEY_AUTHOR);
            }
            if (policy.getDescription() == null || policy.getDescription().isEmpty()) {
                missingFields.add("description");
            }
            if (policy.getDocumentation() == null) {
                missingFields.add("documentation");
            }
            if (policy.getReferences() == null) {
                missingFields.add("references");
            }

            if (!missingFields.isEmpty()) {
                throw new IllegalArgumentException(
                        String.format(
                                Locale.ROOT, Constants.E_400_MISSING_FIELD, String.join(", ", missingFields)));
            }

            // 3. Update policy
            String policyId = this.updatePolicy(policy);

            // Regenerate space hash because policy content changed
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(
                    "Updated draft policy with ID " + policyId, RestStatus.OK.getStatus());
        } catch (IOException | IllegalArgumentException e) {
            log.warn("Validation error during policy update: {}", e.getMessage());
            return new RestResponse(
                    Constants.E_400_INVALID_JSON_CONTENT + " " + e.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            log.error(e.getMessage());
            return new RestResponse(
                    Constants.E_500_POLICY_UPDATE_FAILED + " " + e.getMessage(),
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
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
                    String.format(
                            Locale.ROOT,
                            Constants.E_500_UNEXPECTED_INDEX_STATE,
                            Constants.KEY_DOCUMENT,
                            Space.DRAFT,
                            Constants.INDEX_POLICIES));
        }

        // Validate integrations: allow reordering but prevent addition/removal
        List<String> currentIntegrations =
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyList());
        List<String> newIntegrations = policy.getIntegrations();

        Set<String> currentSet = new HashSet<>(currentIntegrations);
        Set<String> newSet = new HashSet<>(newIntegrations);

        if (!currentSet.equals(newSet)) {
            throw new IllegalArgumentException(
                    "Integrations cannot be added or removed via policy update. "
                            + "Please use the integration endpoints.");
        }

        String docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();
        String docCreationDate = currentPolicyDoc.getOrDefault(Constants.KEY_DATE, "").toString();
        String docModificationDate = Instant.now().toString();

        // Update (set or overwrite unmodifiable values in incoming policy document)
        policy.setId(docId);
        policy.setDate(docCreationDate);
        policy.setModified(docModificationDate);
        currentPolicy.put(Constants.KEY_DOCUMENT, policy.toMap());
        // TODO implement policy and space hash calculation
        // currentPolicy.setHash();

        // Update in index
        ContentIndex index = new ContentIndex(this.client, Constants.INDEX_POLICIES, null);
        QueryBuilder query = QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString());
        SearchRequest searchRequest =
                new SearchRequest()
                        .indices(Constants.INDEX_POLICIES)
                        .source(new SearchSourceBuilder().query(query));
        try {
            // TODO replace with SpaceService::findDocumentId()
            SearchResponse searchResponse =
                    this.client
                            .search(searchRequest)
                            .get(PluginSettings.getInstance().getClientTimeout(), TimeUnit.SECONDS);

            if (searchResponse == null || searchResponse.getHits() == null) {
                throw new IllegalStateException("no hits");
            }

            String draftPolicyId = searchResponse.getHits().getAt(0).getId();
            // Convert Map to Gson JsonObject via JSON string
            String jsonString = mapper.writeValueAsString(currentPolicy);
            JsonObject gsonObject = JsonParser.parseString(jsonString).getAsJsonObject();
            IndexResponse indexResponse = index.create(draftPolicyId, gsonObject);

            return indexResponse.getId();
        } catch (Exception e) {
            throw new IllegalStateException("Draft policy not found: " + e.getMessage());
        }
    }
}
