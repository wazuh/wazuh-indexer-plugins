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
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WDeleteIntegrationAction;
import com.wazuh.securityanalytics.action.WDeleteIntegrationRequest;
import com.wazuh.securityanalytics.action.WDeleteIntegrationResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
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

import static org.opensearch.rest.RestRequest.Method.DELETE;

public class RestDeleteIntegrationAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_integration_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_delete";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";

    private final EngineService engine;
    private final ObjectMapper mapper;

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

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        if (request.hasParam("id")) {
            request.param("id");
        }
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    public BytesRestResponse handleRequest(RestRequest request, NodeClient client) throws IOException {
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
                    return this.buildJsonErrorResponse(RestStatus.BAD_REQUEST,
                        "Cannot delete integration from space '" + spaceName + "'. Only 'draft' space is modifiable.");
                }
            } else {
                return this.buildJsonErrorResponse(RestStatus.BAD_REQUEST, "Cannot delete integration with undefined space.");
            }

            // 2. Delete from SAP
            WDeleteIntegrationRequest sapRequest = new WDeleteIntegrationRequest(
                id,
                WriteRequest.RefreshPolicy.IMMEDIATE
            );

            try {
                WDeleteIntegrationResponse sapResponse = client.execute(WDeleteIntegrationAction.INSTANCE, sapRequest).actionGet();
                if (sapResponse.status() == RestStatus.INTERNAL_SERVER_ERROR) {
                    return this.buildJsonErrorResponse(sapResponse.status(), "Failed to delete integration from Security Analytics Plugin");
                }
            } catch (Exception e) {
                // Ignore missing integration in SAP
            }

            // 3. Delete from Local Index
            DeleteRequest localDeleteRequest = new DeleteRequest(CTI_INTEGRATIONS_INDEX, id)
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

    private BytesRestResponse buildJsonErrorResponse(RestStatus status, String message) {
        ObjectNode errorNode = this.mapper.createObjectNode();
        errorNode.put("message", message);
        errorNode.put("status", status.getStatus());
        return new BytesRestResponse(status, errorNode.toString());
    }

    private void removeLinkFromPolicy(NodeClient client, String integrationId) throws IOException {
        SearchRequest searchRequest = new SearchRequest(CTI_POLICIES_INDEX)
            .source(new SearchSourceBuilder()
                .size(1)
                .query(QueryBuilders.matchQuery("space.name", "draft")));

        SearchResponse response = client.search(searchRequest).actionGet();
        if (response.getHits().getHits().length > 0) {
            SearchHit hit = response.getHits().getAt(0);
            String policyId = hit.getId();
            Map<String, Object> source = hit.getSourceAsMap();

            Map<String, Object> document = (Map<String, Object>) source.get("document");
            List<String> integrations = (List<String>) document.getOrDefault("integrations", new ArrayList<>());

            if (integrations.contains(integrationId)) {
                integrations.remove(integrationId);
                document.put("integrations", integrations);

                // Recalculate Hash
                String docString = this.mapper.writeValueAsString(document);
                String newHash = HashCalculator.sha256(docString);

                Map<String, Object> hash = (Map<String, Object>) source.getOrDefault("hash", new HashMap<>());
                hash.put("sha256", newHash);
                source.put("hash", hash);

                IndexRequest updateRequest = new IndexRequest(CTI_POLICIES_INDEX)
                    .id(policyId)
                    .source(source)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                client.index(updateRequest).actionGet();
            }
        }
    }
}
