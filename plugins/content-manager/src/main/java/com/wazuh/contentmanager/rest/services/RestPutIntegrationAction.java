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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
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

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * Updates an integration in the local engine.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestPutIntegrationAction extends BaseRestHandler {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CTI_DECODERS_INDEX = ".cti-decoders";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_KVDBS_INDEX = ".cti-kvdbs";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";
    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String DRAFT_SPACE_NAME = "draft";
    private static final String ENDPOINT_NAME = "content_manager_integration_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_update";

    private ContentIndex integrationsIndex;
    private ContentIndex policiesIndex;
    private final EngineService engine;
    private final SecurityAnalyticsService service;

    /**
     * @param engine The service instance to communicate with the local engine service.
     * @param service The service instance to communicate with the Security Analytics Plugin.
     */
    public RestPutIntegrationAction(EngineService engine, SecurityAnalyticsService service) {
        this.engine = engine;
        this.service = service;
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
                        .path(PluginSettings.INTEGRATIONS_URI + "/{id}")
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        this.policiesIndex = new ContentIndex(client, CTI_POLICIES_INDEX, null);
        this.integrationsIndex = new ContentIndex(client, CTI_INTEGRATIONS_INDEX, null);
        return channel ->
                channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
    }

    /**
     * @param request incoming request
     * @param client the node client
     * @return a BytesRestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public RestResponse handleRequest(RestRequest request, Client client) throws IOException {

        // Extract ID from path parameter
        String id = request.param("id");
        if (id == null || id.isBlank()) {
            return new RestResponse(
                    "Path parameter `id` is required.", RestStatus.BAD_REQUEST.getStatus());
        }

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
        JsonNode requestPayload;
        try {
            requestPayload = MAPPER.readTree(request.content().streamInput());
        } catch (IOException ex) {
            return new RestResponse("Invalid JSON content.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Verify request is of type "integration"
        if (!requestPayload.has("type") || !requestPayload.get("type").asText().equals("integration")) {
            return new RestResponse("Invalid request type.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Check a document with the solicited Id exists in the integrations index
        if (!this.integrationsIndex.exists(id)) {
            return new RestResponse(
                    "Integration with id {id} could not be found", RestStatus.BAD_REQUEST.getStatus());
        }

        // Check that the Id is in the policy's integrations array
        BoolQueryBuilder query =
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("document.integrations", id))
                        .must(QueryBuilders.termQuery("space.name", DRAFT_SPACE_NAME));
        if (this.policiesIndex.searchByQuery(query) == null) {
            return new RestResponse(
                    "Integration with id {id} is not associated with any policy.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Extract /resource and /resource/document nodes
        JsonNode integrationNode = requestPayload.at("/resource");
        JsonNode documentNode = integrationNode.at("/document");
        if (!documentNode.isObject() || !integrationNode.isObject()) {
            return new RestResponse(
                    "Invalid JSON structure: /resource/document must be an object.",
                    RestStatus.BAD_REQUEST.getStatus());
        }
        ObjectNode documentObject = (ObjectNode) documentNode;

        // Insert ID into /document/id
        documentObject.put("id", id);

        // Insert "draft" into /space/name
        ((ObjectNode) integrationNode).putObject("space").put("name", DRAFT_SPACE_NAME);

        // Calculate and add a hash to the integration
        String hash = HashCalculator.sha256(documentNode.toString());
        ((ObjectNode) integrationNode).putObject("hash").put("sha256", hash);

        // Update integration in SAP
        WIndexIntegrationResponse sapResponse = service.upsertIntegration(documentNode);

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
        RestResponse validationResponse = this.engine.validate(requestPayload);

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
            IndexResponse integrationUpdateResponse = this.integrationsIndex.create(id, integrationNode);

            // Check update response. We are expecting for a 200 OK status.
            if (integrationUpdateResponse == null
                    || integrationUpdateResponse.status() != RestStatus.OK) {
                // otherwise, we delete the created SAP integration and return an error.
                service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to update integration.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
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
                    "Integration with ID {id} updated successfully : ", RestStatus.OK.getStatus());
        } catch (Exception e) {
            service.deleteIntegration(id);
            return new RestResponse(
                    "Unexpected error during processing.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
