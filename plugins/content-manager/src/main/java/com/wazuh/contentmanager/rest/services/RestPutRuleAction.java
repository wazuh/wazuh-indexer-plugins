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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.DocumentValidations;
import com.wazuh.securityanalytics.action.WIndexCustomRuleAction;
import com.wazuh.securityanalytics.action.WIndexCustomRuleRequest;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * PUT /_plugins/content-manager/rules/{rule_id}
 *
 * <p>Updates a rule in the local engine and the CTI index.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestPutRuleAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_rule_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/rule_update";
    private static final Logger log = LogManager.getLogger(RestPutRuleAction.class);

    private static final String CTI_RULES_INDEX = ".cti-rules";

    /** Default constructor. */
    public RestPutRuleAction() {}

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
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepare the request for execution.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a {@link RestChannelConsumer} that executes the update operation
     * @throws IOException if an I/O error occurs
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        if (request.hasParam("id")) {
            request.param("id");
        }
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /**
     * Handles the update rule request.
     *
     * <p>This method performs the following steps:
     *
     * <ol>
     *   <li>Validates the presence of the {@code rule_id} parameter and request body.
     *   <li>Parses the request body ensuring it follows the { "type": "rule", "resource": {...} }
     *       structure.
     *   <li>Injects metadata fields such as {@code modified} timestamp and default {@code enabled}
     *       status.
     *   <li>Calls the Security Analytics Plugin (SAP) to update the rule in the engine.
     *   <li>Calculates the SHA-256 hash of the updated rule document.
     *   <li>Updates the rule document in the CTI rules index.
     * </ol>
     *
     * @param request the incoming REST request containing the rule update data
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

            // Validate rule exists and is in draft space
            String validationError =
                    DocumentValidations.validateDocumentInSpace(client, CTI_RULES_INDEX, ruleId, "Rule");
            if (validationError != null) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse(validationError, RestStatus.BAD_REQUEST.getStatus()).toXContent());
            }

            if (!request.hasContent()) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse("Missing request body", RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(request.content().streamInput());

            // 1. Validate Wrapper Structure
            if (!rootNode.has("type") || !"rule".equals(rootNode.get("type").asText())) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse(
                                        "Invalid or missing 'type'. Expected 'rule'.",
                                        RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }

            if (!rootNode.has("resource")) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse("Missing 'resource' field.", RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }

            JsonNode resourceNode = rootNode.get("resource");

            // 2. Validate Resource Fields
            if (resourceNode.has("date") || resourceNode.has("modified")) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse(
                                        "Fields 'date' and 'modified' are managed by the system.",
                                        RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }

            ObjectNode ruleNode = resourceNode.deepCopy();

            ContentIndex rulesIndex = new ContentIndex(client, CTI_RULES_INDEX);
            String createdDate = null;
            String existingAuthor = null;

            JsonNode existingDoc = rulesIndex.getDocument(ruleId);
            if (existingDoc != null && existingDoc.has("document")) {
                JsonNode doc = existingDoc.get("document");
                if (doc.has("date")) {
                    createdDate = doc.get("date").asText();
                }
                if (doc.has("author")) {
                    existingAuthor = doc.get("author").asText();
                }
            }

            ruleNode.put(
                    "date", Objects.requireNonNullElseGet(createdDate, () -> Instant.now().toString()));
            ruleNode.put("modified", Instant.now().toString());

            if (!ruleNode.has("enabled")) {
                ruleNode.put("enabled", true);
            }
            if (!ruleNode.has("author")) {
                ruleNode.put("author", existingAuthor != null ? existingAuthor : "Wazuh (generated)");
            }

            String product = ContentIndex.extractProduct(ruleNode);

            // 3. Call SAP
            ruleNode.put("id", ruleId);
            WIndexCustomRuleRequest ruleRequest =
                    new WIndexCustomRuleRequest(
                            ruleId,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            product,
                            org.opensearch.rest.RestRequest.Method.POST,
                            ruleNode.toString(),
                            true // forced
                            );
            client.execute(WIndexCustomRuleAction.INSTANCE, ruleRequest).actionGet();

            // 4. Update CTI Rules Index
            rulesIndex.indexCtiContent(ruleId, ruleNode, "draft");

            RestResponse response =
                    new RestResponse("Rule updated successfully", RestStatus.OK.getStatus());
            return new BytesRestResponse(RestStatus.OK, response.toXContent());

        } catch (Exception e) {
            log.error("Error updating rule: {}", e.getMessage(), e);
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
