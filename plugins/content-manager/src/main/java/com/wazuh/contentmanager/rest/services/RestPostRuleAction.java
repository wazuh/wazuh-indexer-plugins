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
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;
import com.wazuh.contentmanager.utils.DocumentValidations;
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
    private PolicyHashService policyHashService;

    /** Default constructor. */
    public RestPostRuleAction() {}

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
        this.policyHashService = new PolicyHashService(client);
        RestResponse response = this.handleRequest(request, client);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    /**
     * Handles the rule creation request.
     *
     * <p>This method performs the following steps:
     *
     * <ol>
     *   <li>Validates the request body structure (type: "rule", resource: {...}).
     *   <li>Validates the resource fields (e.g., {@code integration}).
     *   <li>Ensures the payload does not contain an {@code id} field.
     *   <li>Calls the Security Analytics Plugin (SAP) to create the rule in the engine.
     *   <li>Calculates the SHA-256 hash of the rule document.
     *   <li>Indexes the rule in the CTI rules index.
     *   <li>Updates the corresponding integration in the CTI integrations index to link the new rule.
     * </ol>
     *
     * @param request the incoming REST request
     * @param client the client to execute actions
     * @return a {@link RestResponse} indicating the outcome of the operation
     */
    public RestResponse handleRequest(RestRequest request, Client client) {
        try {
            if (!request.hasContent()) {
                return new RestResponse("Missing request body", RestStatus.BAD_REQUEST.getStatus());
            }

            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(request.content().streamInput());

            // 1. Validate Wrapper Structure
            if (!rootNode.has(Constants.KEY_TYPE)
                    || !Constants.KEY_RULE.equals(rootNode.get(Constants.KEY_TYPE).asText())) {
                return new RestResponse(
                        "Invalid or missing 'type'. Expected 'rule'.", RestStatus.BAD_REQUEST.getStatus());
            }

            if (!rootNode.has(Constants.KEY_RESOURCE)) {
                return new RestResponse("Missing 'resource' field.", RestStatus.BAD_REQUEST.getStatus());
            }

            JsonNode resourceNode = rootNode.get(Constants.KEY_RESOURCE);

            // 2. Validate Payload (Resource)
            if (resourceNode.has(Constants.KEY_ID)) {
                return new RestResponse(
                        "ID must not be provided during creation", RestStatus.BAD_REQUEST.getStatus());
            }
            if (!rootNode.has(Constants.KEY_INTEGRATION)) {
                return new RestResponse("Integration ID is required", RestStatus.BAD_REQUEST.getStatus());
            }

            String integrationId = rootNode.get(Constants.KEY_INTEGRATION).asText();

            // Validate that the Integration exists and is in draft space
            String spaceValidationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus());
            }

            String ruleId = UUID.randomUUID().toString();

            // Prepare rule object
            ObjectNode ruleNode = resourceNode.deepCopy();
            ruleNode.put(Constants.KEY_ID, ruleId);

            // Metadata operations
            if (!ruleNode.has(Constants.KEY_DATE)) {
                ruleNode.put(Constants.KEY_DATE, Instant.now().toString());
            }
            if (!ruleNode.has(Constants.KEY_ENABLED)) {
                ruleNode.put(Constants.KEY_ENABLED, true);
            }

            String product = ContentIndex.extractProduct(ruleNode);
            String payloadString = ruleNode.toString();

            // 3. Call SAP -> Custom Action
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

            // 4. Store in CTI Rules Index
            ContentIndex rulesIndex = new ContentIndex(client, Constants.INDEX_RULES);
            rulesIndex.indexCtiContent(ruleId, ruleNode, Space.DRAFT.toString());

            // 5. Link in Integration
            ContentUtils.linkResourceToIntegration(client, integrationId, ruleId, Constants.KEY_RULES);

            // 6. Regenerate space hash because rule was added to space
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(
                    "Custom rule created successfully with ID " + ruleId, RestStatus.CREATED.getStatus());

        } catch (Exception e) {
            log.error("Error creating rule: {}", e.getMessage(), e);
            // If validation error return bad request
            if (e.getMessage() != null && e.getMessage().contains("Invalid rule")) {
                return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
            }
            return new RestResponse(e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
