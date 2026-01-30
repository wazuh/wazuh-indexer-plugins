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

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
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
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import com.wazuh.securityanalytics.action.WIndexIntegrationRequest;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;
import com.wazuh.securityanalytics.model.Integration;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST Handler for creating new Integrations in the Content Manager.
 *
 * <p>This handler processes POST requests to create integrations. It orchestrates validation via
 * the Engine, creation in the Security Analytics Plugin (SAP), and storage in the local index. All
 * created integrations are automatically assigned to the "draft" space and added to the draft
 * policy.
 *
 * <p>Endpoint: POST /_plugins/_content_manager/integrations
 */
public class RestPostIntegrationAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_integration_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_create";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";
    private static final String DRAFT_PREFIX = "d_";

    private final EngineService engine;
    private final ObjectMapper mapper;

    /**
     * Constructs a new RestPostIntegrationAction.
     *
     * @param engine The EngineService used for validating the integration resource.
     */
    public RestPostIntegrationAction(EngineService engine) {
        this.engine = engine;
        this.mapper = new ObjectMapper();
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.INTEGRATIONS_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /**
     * Handles the creation request for an integration.
     *
     * <p>The flow is as follows:
     *
     * <ol>
     *   <li>Validates the request body structure (must contain 'resource' and no ID).
     *   <li>Generates a new UUID (rawId) and a draft ID (d_UUID).
     *   <li>Validates the resource using the {@link EngineService}.
     *   <li>Indexes the integration in the Security Analytics Plugin (SAP) using the draft ID.
     *   <li>Indexes the integration in the local CTI index with metadata (hash, space).
     *   <li>Updates the Draft Policy to include the new integration ID.
     * </ol>
     *
     * @param request The REST request.
     * @param client The OpenSearch client.
     * @return A BytesRestResponse containing the result of the operation.
     * @throws IOException If an I/O error occurs.
     */
    public BytesRestResponse handleRequest(RestRequest request, NodeClient client)
            throws IOException {
        try {
            if (!request.hasContent()) {
                return new BytesRestResponse(RestStatus.BAD_REQUEST, "Request body is missing");
            }

            JsonNode requestBody = this.mapper.readTree(request.content().utf8ToString());

            // Validate Input Structure
            if (!requestBody.has("resource")) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST, "Request body must contain 'resource' field");
            }

            ObjectNode resourceNode = (ObjectNode) requestBody.get("resource");

            if (resourceNode.has("id")) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST, "ID must not be provided during creation");
            }

            if (resourceNode.has("date")) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST, "'date' must not be provided during creation");
            }

            if (resourceNode.has("modified")) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST, "'modified' must not be provided during creation");
            }

            String rawId = UUID.randomUUID().toString();
            String draftId = DRAFT_PREFIX + rawId;
            String date = LocalDate.now().toString();

            // 1. Prepare payload for Engine and Local Index
            resourceNode.put("id", rawId);

            if (resourceNode.has("name") && !resourceNode.has("title")) {
                resourceNode.put("title", resourceNode.get("name").asText());
            }

            resourceNode.put("date", date);
            if (!resourceNode.has("enabled")) resourceNode.put("enabled", true);

            // 2. Engine Validation
            ObjectNode validationPayload = (ObjectNode) requestBody;
            if (!validationPayload.has("type")) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST, "Request body must contain 'type' field");
            }

            RestResponse validationResponse = this.engine.validate(validationPayload);
            if (validationResponse.getStatus() != RestStatus.OK.getStatus()) {
                return new BytesRestResponse(
                        RestStatus.fromCode(validationResponse.getStatus()), validationResponse.getMessage());
            }

            // 3. SAP Execution
            Map<String, Object> sapMap = this.mapper.convertValue(resourceNode, Map.class);
            if (sapMap.containsKey("category")) {
                String rawCategory = (String) sapMap.get("category");
                sapMap.put("category", this.formatCategory(rawCategory));
            }

            Integration integration = new Integration(sapMap);
            integration.setId(draftId);

            WIndexIntegrationRequest sapRequest =
                    new WIndexIntegrationRequest(
                            draftId,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            org.opensearch.rest.RestRequest.Method.POST,
                            integration);

            WIndexIntegrationResponse sapResponse =
                    client.execute(WIndexIntegrationAction.INSTANCE, sapRequest).actionGet();
            if (sapResponse.status() != RestStatus.CREATED && sapResponse.status() != RestStatus.OK) {
                return new BytesRestResponse(
                        sapResponse.status(), "Failed to create integration in Security Analytics Plugin");
            }

            // 4. Local Indexing
            ObjectNode rootNode = this.mapper.createObjectNode();
            rootNode.set("document", resourceNode);

            String sha256 = HashCalculator.sha256(resourceNode.toString());
            ObjectNode hashNode = this.mapper.createObjectNode();
            hashNode.put("sha256", sha256);
            rootNode.set("hash", hashNode);

            ObjectNode spaceNode = this.mapper.createObjectNode();
            spaceNode.put("name", "draft");
            rootNode.set("space", spaceNode);

            IndexRequest localIndexRequest =
                    new IndexRequest(CTI_INTEGRATIONS_INDEX)
                            .id(draftId)
                            .source(rootNode.toString(), XContentType.JSON)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

            client.index(localIndexRequest).actionGet();

            this.updateDraftPolicy(client, draftId);

            // 5. Response
            ObjectNode responseNode = this.mapper.createObjectNode();
            responseNode.put("message", "Integration created successfully");
            responseNode.put("id", draftId);

            return new BytesRestResponse(RestStatus.CREATED, responseNode.toString());

        } catch (Exception e) {
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Formats the category string to Title Case to match Security Analytics Plugin expectations.
     * e.g., "cloud-services" -> "Cloud Services".
     *
     * @param category The raw category slug.
     * @return The formatted category string.
     */
    private String formatCategory(String category) {
        if (category == null || category.isEmpty()) return "Other";
        if (category.contains("cloud-services")) {
            category = category.substring(0, 14);
        }
        return Arrays.stream(category.split("-"))
                .map(s -> s.substring(0, 1).toUpperCase() + s.substring(1))
                .collect(Collectors.joining(" "));
    }

    /**
     * Updates the Draft Policy by adding the new integration ID. Also recalculates the policy hash.
     *
     * @param client The NodeClient to execute searches and updates.
     * @param integrationId The ID of the integration to add (should be the draft ID).
     * @throws IOException If a serialization error occurs.
     */
    private void updateDraftPolicy(NodeClient client, String integrationId) throws IOException {
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

            if (!integrations.contains(integrationId)) {
                integrations.add(integrationId);
                document.put("integrations", integrations);

                // Recalculate Hash of the modified document
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
}
