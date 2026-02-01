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
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WDeleteIntegrationAction;
import com.wazuh.securityanalytics.action.WDeleteIntegrationRequest;
import com.wazuh.securityanalytics.action.WDeleteIntegrationResponse;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST Handler for deleting Integrations in the Content Manager.
 *
 * <p>This handler processes DELETE requests to remove integrations. It ensures that only
 * integrations in the "draft" space can be deleted. It handles deletion from the SAP, the local
 * index, and removes the reference from the draft policy.
 *
 * <p><strong>Endpoint:</strong> DELETE /_plugins/_content_manager/integrations/{id}
 */
public class RestDeleteIntegrationAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_integration_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_delete";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";

    private final EngineService engine;
    private SecurityAnalyticsService service;
    private final ObjectMapper mapper;

    /**
     * Constructs a new RestDeleteIntegrationAction.
     *
     * @param engine The EngineService (unused in delete but consistent with other actions).
     */
    public RestDeleteIntegrationAction(EngineService engine) {
        this.engine = engine;
        this.mapper = new ObjectMapper();
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the delete endpoint
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

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
        throws IOException {
        request.param("id");
        this.setSecurityAnalyticsService(new SecurityAnalyticsServiceImpl(client));
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /**
     * Handles the delete request for an integration.
     *
     * <p>The flow is as follows:
     *
     * <ol>
     *   <li>Validates the integration exists in the local index and belongs to "draft" space.
     *   <li>Deletes the integration from the Security Analytics Plugin (SAP).
     *   <li>Deletes the integration from the local CTI index.
     *   <li>Removes the integration ID from the Draft Policy and updates the hash.
     * </ol>
     *
     * @param request The REST request.
     * @param client The OpenSearch client.
     * @return A BytesRestResponse containing the operation status.
     * @throws IOException If an I/O error occurs.
     */
    public BytesRestResponse handleRequest(RestRequest request, NodeClient client)
        throws IOException {
        try {
            String id = request.param("id");
            if (id == null || id.isEmpty()) {
                return this.buildJsonErrorResponse(RestStatus.BAD_REQUEST, "Integration ID is required");
            }

            // 1. Validate existence and space in Local Index
            GetRequest getRequest = new GetRequest(CTI_INTEGRATIONS_INDEX, id);
            GetResponse getResponse = client.get(getRequest).actionGet();

            if (!getResponse.isExists()) {
                return this.buildJsonErrorResponse(RestStatus.NOT_FOUND, "Integration not found: " + id);
            }

            Map<String, Object> source = getResponse.getSourceAsMap();
            if (source.containsKey("space")) {
                Map<String, Object> space = (Map<String, Object>) source.get("space");
                String spaceName = (String) space.get("name");
                if (!"draft".equals(spaceName)) {
                    return this.buildJsonErrorResponse(
                        RestStatus.BAD_REQUEST,
                        "Cannot delete integration from space '"
                            + spaceName
                            + "'. Only 'draft' space is modifiable.");
                }
            } else {
                return this.buildJsonErrorResponse(
                    RestStatus.BAD_REQUEST, "Cannot delete integration with undefined space.");
            }

            // 2. Delete from SAP
            WDeleteIntegrationRequest sapRequest =
                new WDeleteIntegrationRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE);

            this.service.deleteIntegration(id);

            // 3. Delete from Local Index
            DeleteRequest localDeleteRequest =
                new DeleteRequest(CTI_INTEGRATIONS_INDEX, id)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

            client.delete(localDeleteRequest).actionGet();

            // 4. Update Policy
            this.removeLinkFromPolicy(client, id);

            // Construct JSON response for success
            ObjectNode responseNode = this.mapper.createObjectNode();
            responseNode.put("message", "Integration deleted successfully");
            responseNode.put("status", RestStatus.OK.getStatus());

            return new BytesRestResponse(RestStatus.OK, responseNode.toString());

        } catch (Exception e) {
            return this.buildJsonErrorResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Builds a standardized JSON error response.
     *
     * <p>Constructs a JSON object containing the error message and the HTTP status code, then wraps
     * it in a {@link BytesRestResponse}.
     *
     * @param status The HTTP status code to return.
     * @param message The error message description.
     * @return A BytesRestResponse containing the JSON error details.
     */
    private BytesRestResponse buildJsonErrorResponse(RestStatus status, String message) {
        ObjectNode errorNode = this.mapper.createObjectNode();
        errorNode.put("message", message);
        errorNode.put("status", status.getStatus());
        return new BytesRestResponse(status, errorNode.toString());
    }

    /**
     * Removes the integration ID from the Draft Policy and updates the policy's hash.
     *
     * <p>This method searches for the policy associated with the "draft" space. If found, it checks
     * if the integration ID is present in the policy's integration list. If present, the ID is
     * removed, the policy document hash is recalculated, and the policy is updated in the index.
     *
     * @param client The NodeClient used to execute search and index requests.
     * @param integrationId The ID of the integration to remove.
     * @throws IOException If a serialization error occurs during hash recalculation.
     */
    private void removeLinkFromPolicy(NodeClient client, String integrationId) throws IOException {
        SearchRequest searchRequest =
            new SearchRequest(CTI_POLICIES_INDEX)
                .source(
                    new SearchSourceBuilder()
                        .size(1)
                        .query(QueryBuilders.matchQuery("space.name", "draft")));

        SearchResponse response = client.search(searchRequest).actionGet();
        if (response.getHits().getHits().length > 0) {
            SearchHit hit = response.getHits().getAt(0);
            String policyId = hit.getId();
            Map<String, Object> source = hit.getSourceAsMap();

            Map<String, Object> document = (Map<String, Object>) source.get("document");
            List<String> integrations =
                (List<String>) document.getOrDefault("integrations", new ArrayList<>());

            if (integrations.contains(integrationId)) {
                integrations.remove(integrationId);
                document.put("integrations", integrations);

                // Recalculate Hash
                String docString = this.mapper.writeValueAsString(document);
                String newHash = HashCalculator.sha256(docString);

                Map<String, Object> hash =
                    (Map<String, Object>) source.getOrDefault("hash", new HashMap<>());
                hash.put("sha256", newHash);
                source.put("hash", hash);

                IndexRequest updateRequest =
                    new IndexRequest(CTI_POLICIES_INDEX)
                        .id(policyId)
                        .source(source)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                client.index(updateRequest).actionGet();
            }
        }
    }

    /**
     * @param service the security analytics service to set
     */
    public void setSecurityAnalyticsService(SecurityAnalyticsService service) {
        this.service = service;
    }
}