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
import java.util.Locale;
import java.util.Objects;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
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

    private PolicyHashService policyHashService;

    /** Default constructor. */
    public RestPutRuleAction() {}

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
        request.param(Constants.KEY_ID);
        this.policyHashService = new PolicyHashService(client);
        return channel ->
                channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
    }

    /**
     * Handles the update rule request.
     *
     * <p>This method performs the following steps:
     *
     * <ol>
     *   <li>Validates the presence of the {@code rule_id} parameter and request body.
     *   <li>Parses the request body ensuring it follows the { Constants.KEY_TYPE: "rule",
     *       Constants.KEY_RESOURCE: {...} } structure.
     *   <li>Injects metadata fields such as {@code modified} timestamp and default {@code enabled}
     *       status.
     *   <li>Calls the Security Analytics Plugin (SAP) to update the rule in the engine.
     *   <li>Calculates the SHA-256 hash of the updated rule document.
     *   <li>Updates the rule document in the CTI rules index.
     * </ol>
     *
     * @param request the incoming REST request containing the rule update data
     * @param client the client to execute OpenSearch actions
     * @return a {@link RestResponse} indicating the outcome of the operation
     */
    public RestResponse handleRequest(RestRequest request, Client client) {
        try {
            String ruleId = request.param(Constants.KEY_ID);

            // Validate ID is present
            if (ruleId == null || ruleId.isEmpty()) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_FIELD_IS_REQUIRED, Constants.KEY_ID),
                        RestStatus.BAD_REQUEST.getStatus());
            }

            // Validate UUID format
            try {
                java.util.UUID.fromString(ruleId);
            } catch (IllegalArgumentException e) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_INVALID_UUID, ruleId),
                        RestStatus.BAD_REQUEST.getStatus());
            }

            // Check if rule exists
            ContentIndex rulesIndex = new ContentIndex(client, Constants.INDEX_RULES);
            if (!rulesIndex.exists(ruleId)) {
                return new RestResponse(
                        Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
            }

            // Validate rule is in draft space
            String validationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_RULES, ruleId, Constants.KEY_RULE);
            if (validationError != null) {
                return new RestResponse(validationError, RestStatus.BAD_REQUEST.getStatus());
            }

            if (!request.hasContent()) {
                return new RestResponse(
                        Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
            }

            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode;
            try {
                rootNode = mapper.readTree(request.content().streamInput());
            } catch (IOException e) {
                return new RestResponse(
                        Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
            }

            // 1. Validate Wrapper Structure
            if (!rootNode.has(Constants.KEY_TYPE)
                    || !Constants.KEY_RULE.equals(rootNode.get(Constants.KEY_TYPE).asText())) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_INVALID_FIELD_FORMAT, Constants.KEY_TYPE),
                        RestStatus.BAD_REQUEST.getStatus());
            }

            if (!rootNode.has(Constants.KEY_RESOURCE)) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_FIELD_IS_REQUIRED, Constants.KEY_RESOURCE),
                        RestStatus.BAD_REQUEST.getStatus());
            }

            JsonNode resourceNode = rootNode.get(Constants.KEY_RESOURCE);

            // 2. Validate Resource Fields
            if (resourceNode.has(Constants.KEY_DATE) || resourceNode.has(Constants.KEY_MODIFIED)) {
                return new RestResponse(
                        Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
            }

            ObjectNode ruleNode = resourceNode.deepCopy();

            String createdDate = null;
            String existingAuthor = null;

            JsonNode existingDoc = rulesIndex.getDocument(ruleId);
            if (existingDoc != null && existingDoc.has(Constants.KEY_DOCUMENT)) {
                JsonNode doc = existingDoc.get(Constants.KEY_DOCUMENT);
                if (doc.has(Constants.KEY_DATE)) {
                    createdDate = doc.get(Constants.KEY_DATE).asText();
                }
                if (doc.has(Constants.KEY_AUTHOR)) {
                    existingAuthor = doc.get(Constants.KEY_AUTHOR).asText();
                }
            }

            ruleNode.put(
                    Constants.KEY_DATE,
                    Objects.requireNonNullElseGet(createdDate, () -> Instant.now().toString()));
            ruleNode.put(Constants.KEY_MODIFIED, Instant.now().toString());

            if (!ruleNode.has(Constants.KEY_ENABLED)) {
                ruleNode.put(Constants.KEY_ENABLED, true);
            }
            if (!ruleNode.has(Constants.KEY_AUTHOR)) {
                ruleNode.put(
                        Constants.KEY_AUTHOR, existingAuthor != null ? existingAuthor : "Wazuh (generated)");
            }

            String product = ContentIndex.extractProduct(ruleNode);

            // 3. Call SAP
            ruleNode.put(Constants.KEY_ID, ruleId);
            try {
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
            } catch (Exception e) {
                log.error("SAP rule update failed: {}", e.getMessage(), e);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // 4. Update CTI Rules Index
            rulesIndex.indexCtiContent(ruleId, ruleNode, Space.DRAFT.toString());

            // 5. Regenerate space hash because rule content changed
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(ruleId, RestStatus.OK.getStatus());

        } catch (Exception e) {
            log.error("Error updating rule: {}", e.getMessage(), e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
