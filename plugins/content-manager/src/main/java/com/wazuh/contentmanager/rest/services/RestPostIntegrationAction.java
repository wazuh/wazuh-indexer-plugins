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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.common.UUIDs;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * TODO !CHANGE_ME POST /_plugins/content-manager/integrations
 *
 * <p>Creates an integration in the local engine.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestPostIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_create";

    /**
     * @TODO: To be deleted. This needs to be retrieved from a single source of truth.
     */
    private static final String CTI_DECODERS_INDEX = ".cti-decoders";

    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_KVDBS_INDEX = ".cti-kvdbs";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";
    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String DRAFT_SPACE_NAME = "draft";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private ContentIndex integrationsIndex;
    private ContentIndex policiesIndex;

    private final EngineService engine;
    private final SecurityAnalyticsService service;

    /**
     * Constructs a new TODO !CHANGE_ME.
     *
     * @param engine The service instance to communicate with the local engine service.
     * @param service The service instance to communicate with the security analytics service.
     */
    public RestPostIntegrationAction(EngineService engine, SecurityAnalyticsService service) {
        this.service = service;
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
                        .path(PluginSettings.INTEGRATIONS_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        this.integrationsIndex = new ContentIndex(client, CTI_INTEGRATIONS_INDEX, null);
        this.policiesIndex = new ContentIndex(client, CTI_POLICIES_INDEX, null);
        return channel ->
                channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request incoming request
     * @param client the node client
     * @return a RestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public RestResponse handleRequest(RestRequest request, Client client) throws IOException {
        // Check if engine service exists
        if (this.engine == null) {
            return new RestResponse(
                    "Engine instance is null.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Check if security analytics service exists
        if (this.service == null) {
            return new RestResponse(
                    "Security Analytics service instance is null.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Check request's payload exists
        if (!request.hasContent()) {
            return new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Check request's payload is valid JSON
        final JsonNode requestPayload;
        try {
            requestPayload = MAPPER.readTree(request.content().streamInput());
        } catch (IOException ex) {
            return new RestResponse("Invalid JSON content.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Verify request is of type "integration"
        if (!requestPayload.has("type") || !requestPayload.get("type").asText().equals("integration")) {
            return new RestResponse("Invalid request type.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Check that there is no ID field
        if (!requestPayload.at("/resource/document/id").isMissingNode()) {
            return new RestResponse(
                    "ID field is not allowed in the request body.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Generate ID
        final String id = "d_" + UUIDs.base64UUID();

        // Extract /resource and /resource/document nodes
        JsonNode integrationNode = requestPayload.at("/resource");
        final JsonNode documentNode = requestPayload.at("/resource/document");
        if (!documentNode.isObject()) {
            return new RestResponse(
                    "Invalid JSON structure: /resource/document must be an object.",
                    RestStatus.BAD_REQUEST.getStatus());
        }
        final ObjectNode documentObject = (ObjectNode) documentNode;

        // Insert ID into /document/id
        documentObject.put("id", id);

        // Insert "draft" into /resource/document/space/name
        documentObject.putObject("space").put("name", DRAFT_SPACE_NAME);

        // Calculate and add a hash to the integration
        String hash = HashCalculator.sha256(documentNode.toString());
        ((ObjectNode) integrationNode).putObject("hash").put("sha256", hash);

        // Create integration in SAP
        final WIndexIntegrationResponse sapResponse = service.upsertIntegration(requestPayload);

        // Check if SAP response is valid
        if (sapResponse == null || sapResponse.getStatus() == null) {
            return new RestResponse(
                    "Failed to create Integration, SAP response is null.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // If SAP response is not OK, return error
        if (sapResponse.getStatus() != RestStatus.OK) {
            return new RestResponse(
                    "Failed to create Integration, SAP response: " + sapResponse.getStatus(),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Validate integration with Wazuh Engine
        final RestResponse validationResponse = this.engine.validate(requestPayload);

        // If validation failed, delete the created integration in SAP
        if (validationResponse.getStatus() != RestStatus.OK.getStatus()) {
            service.deleteIntegration(id);
            return new RestResponse(
                    "Failed to create Integration, Validation response: "
                            + validationResponse.getStatus()
                            + ".",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // From here on, we should roll back SAP integration on any error to avoid partial state.
        try {
            // Index the integration into CTI integrations index (sync + check response)
            IndexResponse integrationIndexResponse = this.integrationsIndex.create(id, integrationNode);

            // Check indexing response. We are expecting for a 200 OK status.
            if (integrationIndexResponse == null || integrationIndexResponse.status() != RestStatus.OK) {
                // otherwise, we delete the created SAP integration and return an error.
                service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to index integration.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Search for the draft policy (scoped to policies index, limit 1)
            TermQueryBuilder queryBuilder = new TermQueryBuilder("document.space.name", DRAFT_SPACE_NAME);

            SearchResponse searchResponse =
                    client
                            .search(
                                    new SearchRequest(CTI_POLICIES_INDEX)
                                            .source(new SearchSourceBuilder().query(queryBuilder).size(1)))
                            .actionGet();

            // If we cannot find the draft space policy, rollback and return an error.
            if (searchResponse.getHits() == null || searchResponse.getHits().getHits().length != 1) {
                // Rollback: delete created integration in CTI index and in SAP
                DeleteRequest deleteRequest = new DeleteRequest(CTI_INTEGRATIONS_INDEX).id(id);
                client.delete(deleteRequest).actionGet();
                service.deleteIntegration(id);
                return new RestResponse(
                        "Draft policy not found.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Get the policy document
            JsonNode draftPolicyNode = MAPPER.readTree(searchResponse.getHits().getAt(0).getSourceAsString());
            JsonNode documentJsonObject = draftPolicyNode.at("/_source/document");
            if (documentJsonObject.isMissingNode()) {
                return new RestResponse(
                    "Failed to retrieve draft policy document.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Get the policy Id
            String policyId = searchResponse.getHits().getAt(0).getId();

            // Retrieve the integrations array from the policy document
            ArrayNode integrationsArray = (ArrayNode) documentJsonObject.get("integrations");
            if (integrationsArray == null || !integrationsArray.isArray()) {
                service.deleteIntegration(id);
                return new RestResponse(
                    "Failed to retrieve integrations array from draft policy document.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Add the new integration ID to the integrations array (avoid duplicates)
            for (JsonNode existing : integrationsArray) {
                if (id.equals(existing.asText())) {
                    // Integration ID already exists in the policy
                    service.deleteIntegration(id);
                    return new RestResponse(
                            "Integration ID already exists in the draft policy.",
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                }
            }
            ((ArrayNode) integrationsArray).add(id);

            // Update the policies own hash
            String policyHash = HashCalculator.sha256(documentJsonObject.asText());

            // Put policyHash inside hash.sha256 key
            ((ObjectNode) draftPolicyNode.at("/_source/hash")).put("sha256", policyHash);

            // Index the policy with the updated integrations array
            IndexResponse indexPolicyResponse = this.policiesIndex.create(policyId, draftPolicyNode);

            if (indexPolicyResponse == null || indexPolicyResponse.status() != RestStatus.OK) {
                service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to update draft policy.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Update the space's hash in the policy
            new PolicyHashService(client)
                    .calculateAndUpdate(
                            CTI_POLICIES_INDEX,
                            CTI_INTEGRATIONS_INDEX,
                            CTI_DECODERS_INDEX,
                            CTI_KVDBS_INDEX,
                            CTI_RULES_INDEX,
                            List.of(Space.DRAFT.toString()));

            return new RestResponse(
                    "Integration created successfully with ID: " + id + ".", RestStatus.OK.getStatus());
        } catch (Exception e) {
            service.deleteIntegration(id);
            return new RestResponse(
                    "Unexpected error during processing.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
