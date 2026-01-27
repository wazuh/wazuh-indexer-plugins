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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.delete.DeleteRequest;
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
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WDeleteRuleAction;
import com.wazuh.securityanalytics.action.WDeleteRuleRequest;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/content-manager/rules/{rule_id}
 *
 * <p>Deletes a rule from the local engine, unlinks it from integrations, and removes it from the
 * CTI index.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestDeleteRuleAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_rule_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/rule_delete";
    private static final Logger log = LogManager.getLogger(RestDeleteRuleAction.class);

    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";

    public RestDeleteRuleAction() {}

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
                        .path(PluginSettings.RULES_URI + "/{id}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepare the request for execution.
     *
     * @param request the incoming REST request
     * @param client the node client used to execute actions
     * @return a {@link RestChannelConsumer} that executes the logic
     * @throws IOException if an I/O error occurs
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /**
     * Handles the delete rule request logic.
     *
     * <p>This method performs the following steps:
     *
     * <ol>
     *   <li>Validates the presence of the {@code rule_id} parameter.
     *   <li>Calls the Security Analytics Plugin (SAP) to delete the rule from the engine.
     *   <li>Searches for any integrations that reference this rule and removes the reference.
     *   <li>Deletes the rule document from the CTI rules index.
     * </ol>
     *
     * @param request the incoming REST request containing the rule ID
     * @param client the client to execute OpenSearch actions
     * @return a {@link BytesRestResponse} indicating the outcome of the operation
     */
    public BytesRestResponse handleRequest(RestRequest request, Client client) {
        try {
            String ruleId = request.param("id");
            if (ruleId == null || ruleId.isEmpty()) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse("Rule ID is required", RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }

            // 1. Call SAP to delete rule
            try {
                client
                        .execute(
                                WDeleteRuleAction.INSTANCE,
                                new WDeleteRuleRequest(ruleId, WriteRequest.RefreshPolicy.IMMEDIATE, true))
                        .actionGet();
            } catch (Exception e) {
                log.warn(
                        "Failed to delete rule [{}] from Security Analytics Plugin: {}",
                        ruleId,
                        e.getMessage());
            }

            // 2. Update Integration
            SearchRequest searchRequest = new SearchRequest(CTI_INTEGRATIONS_INDEX);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
            sourceBuilder.query(QueryBuilders.termQuery("document.rules", ruleId));
            searchRequest.source(sourceBuilder);

            try {
                SearchResponse searchResponse = client.search(searchRequest).actionGet();
                for (SearchHit hit : searchResponse.getHits().getHits()) {
                    Map<String, Object> source = hit.getSourceAsMap();
                    if (source.containsKey("document")) {
                        Map<String, Object> doc = (Map<String, Object>) source.get("document");
                        if (doc.containsKey("rules") && doc.get("rules") instanceof List) {
                            List<String> rules = (List<String>) doc.get("rules");
                            if (rules.remove(ruleId)) {
                                doc.put("rules", rules);
                                client
                                        .index(
                                                new IndexRequest(CTI_INTEGRATIONS_INDEX)
                                                        .id(hit.getId())
                                                        .source(source)
                                                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                                        .actionGet();
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Failed to unlink rule [{}] from integrations: {}", ruleId, e.getMessage());
            }

            // 3. Delete from CTI Rules Index
            client
                    .delete(
                            new DeleteRequest(CTI_RULES_INDEX, ruleId)
                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                    .actionGet();

            RestResponse response =
                    new RestResponse("Rule deleted successfully", RestStatus.OK.getStatus());
            return new BytesRestResponse(RestStatus.OK, response.toXContent());

        } catch (Exception e) {
            log.error("Error deleting rule: {}", e.getMessage(), e);
            try {
                return new BytesRestResponse(
                        RestStatus.INTERNAL_SERVER_ERROR,
                        new RestResponse(e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                                .toXContent());
            } catch (IOException ex) {
                return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, "Internal Server Error");
            }
        }
    }
}
