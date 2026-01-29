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
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WIndexCustomRuleAction;
import com.wazuh.securityanalytics.action.WIndexCustomRuleRequest;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/content-manager/rules
 *
 * <p>Creates a rule in the local engine and updates the corresponding integration.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestPostRuleAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_rule_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/rule_create";
    private static final Logger log = LogManager.getLogger(RestPostRuleAction.class);

    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String INTEGRATION_ID_FIELD = "integration_id";

    /** Default constructor. */
    public RestPostRuleAction() {}

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
                        .path(PluginSettings.RULES_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepare the request for execution.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a {@link RestChannelConsumer} that executes the create operation
     * @throws IOException if an I/O error occurs
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /**
     * Handles the rule creation request.
     *
     * <p>This method performs the following steps:
     *
     * <ol>
     *   <li>Validates the request body and required fields (e.g., {@code integration_id}).
     *   <li>Ensures the payload does not contain an {@code id} field.
     *   <li>Calls the Security Analytics Plugin (SAP) to create the rule in the engine.
     *   <li>Calculates the SHA-256 hash of the rule document.
     *   <li>Indexes the rule in the CTI rules index.
     *   <li>Updates the corresponding integration in the CTI integrations index to link the new rule.
     * </ol>
     *
     * @param request the incoming REST request
     * @param client the client to execute actions
     * @return a {@link BytesRestResponse} indicating the outcome of the operation
     */
    public BytesRestResponse handleRequest(RestRequest request, Client client) {
        try {
            if (!request.hasContent()) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse("Missing request body", RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }

            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(request.content().streamInput());

            // 1. Validate payload
            if (rootNode.has("id")) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse(
                                        "ID must not be provided during creation", RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }
            if (!rootNode.has(INTEGRATION_ID_FIELD)) {
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse("Integration ID is required", RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }

            String integrationId = rootNode.get(INTEGRATION_ID_FIELD).asText();

            // Validate that the Integration exists
            ContentIndex integrationIndex = new ContentIndex(client, CTI_INTEGRATIONS_INDEX);
            if (!integrationIndex.exists(integrationId)) {
                log.warn("RestPostRuleAction: Integration ID [{}] does not exist.", integrationId);
                return new BytesRestResponse(
                        RestStatus.BAD_REQUEST,
                        new RestResponse(
                                        "Integration with ID " + integrationId + " does not exist.",
                                        RestStatus.BAD_REQUEST.getStatus())
                                .toXContent());
            }

            String ruleId = UUID.randomUUID().toString();

            // Prepare rule object
            ObjectNode ruleNode = rootNode.deepCopy();
            ruleNode.remove(INTEGRATION_ID_FIELD);
            ruleNode.put("id", ruleId);

            // Metadata operations
            if (!ruleNode.has("date")) {
                ruleNode.put("date", Instant.now().toString());
            }
            if (!ruleNode.has("enabled")) {
                ruleNode.put("enabled", true);
            }

            String product = ContentIndex.extractProduct(ruleNode);
            String payloadString = ruleNode.toString();

            // 2. Call SAP -> Custom Action
            try {
                WIndexCustomRuleRequest ruleRequest =
                        new WIndexCustomRuleRequest(
                                ruleId, WriteRequest.RefreshPolicy.IMMEDIATE, product, POST, payloadString, true);

                client.execute(WIndexCustomRuleAction.INSTANCE, ruleRequest).actionGet();
                log.info("RestPostRuleAction: SAP created rule successfully (Custom).");
            } catch (Exception e) {
                log.error("RestPostRuleAction: SAP creation failed.", e);
                throw e;
            }

            // 3. Store in CTI Rules Index
            ContentIndex rulesIndex = new ContentIndex(client, CTI_RULES_INDEX);
            rulesIndex.indexCtiContent(ruleId, ruleNode, "draft");

            // 4. Link in Integration
            integrationIndex.appendToList(integrationId, "document.rules", ruleId);

            ObjectNode responseNode = mapper.createObjectNode();
            responseNode.put("message", "Rule created successfully");
            responseNode.put("id", ruleId);
            responseNode.put("status", RestStatus.CREATED.getStatus());

            return new BytesRestResponse(RestStatus.CREATED, responseNode.toString());

        } catch (Exception e) {
            log.error("Error creating rule: {}", e.getMessage(), e);
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
