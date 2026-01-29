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

import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
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
import com.wazuh.securityanalytics.action.WDeleteIntegrationResponse;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * TODO !CHANGE_ME DELETE /_plugins/content-manager/integration/{integration_id}
 *
 * <p>Deletes an integration
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestDeleteIntegrationAction extends BaseRestHandler {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CTI_DECODERS_INDEX = ".cti-decoders";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_KVDBS_INDEX = ".cti-kvdbs";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";
    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String DRAFT_SPACE_NAME = "draft";
    private static final String ENDPOINT_NAME = "content_manager_integration_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_delete";

    private ContentIndex integrationsIndex;
    private ContentIndex policiesIndex;
    private final EngineService engine;
    private final SecurityAnalyticsService service;

    /**
     * Constructs a new TODO !CHANGE_ME.
     *
     * @param engine The service instance to communicate with the local engine service.
     * @param service The service instance to communicate with the Security Analytics service.
     */
    public RestDeleteIntegrationAction(EngineService engine, SecurityAnalyticsService service) {
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
                        .method(DELETE)
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
        return channel ->
                channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
    }

    /**
     * TODO !CHANGE_ME.
     *
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

        // Check a document with the solicited Id exists in the integrations index
        if (!this.integrationsIndex.exists(id)) {
            return new RestResponse(
                    "Integration with id {id} could not be found", RestStatus.BAD_REQUEST.getStatus());
        }

        SearchHit[] hits = searchPolicy(client, id);
        if (hits.length == 0) {
            return new RestResponse(
                    "Integration with id {id} is not associated with any policy.",
                    RestStatus.BAD_REQUEST.getStatus());
        }
        // Get the Policy ID
        String policyId = hits[0].getId();

        // Retrieve the draft policy document object
        JsonNode draftPolicyNode = MAPPER.readTree(hits[0].getSourceAsString());
        JsonNode documentJsonObject = draftPolicyNode.at("/_source/document");
        if (documentJsonObject.isMissingNode()) {
            return new RestResponse(
                    "Failed to retrieve draft policy document.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Retrieve the integrations array from the policy document
        ArrayNode integrationsArray = (ArrayNode) documentJsonObject.get("integrations");
        if (integrationsArray == null || !integrationsArray.isArray()) {
            return new RestResponse(
                    "Failed to retrieve integrations array from draft policy document.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Check if the integration ID exists in the integrations array
        boolean integrationFound = false;
        for (JsonNode integrationNode : integrationsArray) {
            if (integrationNode.asText().equals(id)) {
                integrationFound = true;
                break;
            }
        }
        if (!integrationFound) {
            return new RestResponse(
                    "Integration with id {id} is not associated with the draft policy.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Remove the integration ID from the integrations array
        ArrayNode updatedIntegrationsArray = MAPPER.createArrayNode();
        for (JsonNode integrationNode : integrationsArray) {
            if (!integrationNode.asText().equals(id)) {
                updatedIntegrationsArray.add(integrationNode.asText());
            }
        }

        // Update the policy document with the modified integrations array
        ((ObjectNode) documentJsonObject).set("integrations", updatedIntegrationsArray);

        // Update the policies own hash
        String policyHash = HashCalculator.sha256(documentJsonObject.asText());

        // Put policyHash inside hash.sha256 key
        ((ObjectNode) draftPolicyNode.at("/_source/hash")).put("sha256", policyHash);

        // Update the draft policy back into the policies index
        UpdateResponse policyUpdateResponse =
                client
                        .update(
                                new UpdateRequest(CTI_POLICIES_INDEX, policyId)
                                        .doc(
                                                MAPPER.writeValueAsString(draftPolicyNode.get("_source")),
                                                org.opensearch.common.xcontent.XContentType.JSON))
                        .actionGet();

        if (policyUpdateResponse == null || policyUpdateResponse.status() != RestStatus.OK) {
            return new RestResponse(
                    "Failed to update draft policy document.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        try {
            client
                    .prepareIndex(CTI_POLICIES_INDEX)
                    .setId(policyId)
                    .setSource(
                            MAPPER.writeValueAsString(draftPolicyNode.get("_source")),
                            org.opensearch.common.xcontent.XContentType.JSON)
                    .get();
        } catch (Exception e) {
            return new RestResponse(
                    "Failed to update draft policy document.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Update integration in SAP
        WDeleteIntegrationResponse sapResponse = service.deleteIntegration(id);

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

        // From here on, we should roll back SAP integration on any error to avoid partial state.
        try {
            // Index the integration into CTI integrations index (sync + check response)
            DeleteResponse integrationDeleteResponse = this.integrationsIndex.delete(id);

            // Check update response. We are expecting for a 200 OK status.
            if (integrationDeleteResponse == null
                    || integrationDeleteResponse.status() != RestStatus.OK) {
                return new RestResponse(
                        "Failed to delete integration.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
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

    private static SearchHit[] searchPolicy(Client client, String id) {
        // Get the draft policy document
        BoolQueryBuilder query =
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("document.integrations", id))
                        .must(QueryBuilders.termQuery("space.name", DRAFT_SPACE_NAME));
        // TODO: Use a dedicated utils method such as ContentIndex's searchByQuery()
        SearchHit[] hits =
                client
                        .search(
                                new SearchRequest(CTI_POLICIES_INDEX)
                                        .source(new SearchSourceBuilder().query(query)))
                        .actionGet()
                        .getHits()
                        .getHits();
        return hits;
    }
}
