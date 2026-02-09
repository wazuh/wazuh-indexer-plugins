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
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
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
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;
import com.wazuh.contentmanager.utils.DocumentValidations;
import com.wazuh.securityanalytics.action.WDeleteCustomRuleAction;
import com.wazuh.securityanalytics.action.WDeleteCustomRuleRequest;

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

    private PolicyHashService policyHashService;

    /** Default constructor. */
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
        request.param(Constants.KEY_ID);
        this.policyHashService = new PolicyHashService(client);
        RestResponse response = this.handleRequest(request, client);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    /**
     * Sets the policy hash service for testing purposes.
     *
     * @param policyHashService the PolicyHashService instance to use
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
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
     * @return a {@link RestResponse} indicating the outcome of the operation
     */
    public RestResponse handleRequest(RestRequest request, Client client) {
        try {
            String ruleId = request.param(Constants.KEY_ID);

            // Validate ID is present
            RestResponse validationError =
                    DocumentValidations.validateRequiredParam(ruleId, Constants.KEY_ID);
            if (validationError != null) {
                return validationError;
            }

            // Validate UUID format
            validationError = DocumentValidations.validateUUID(ruleId);
            if (validationError != null) {
                return validationError;
            }

            // Check if rule exists
            ContentIndex rulesIndex = new ContentIndex(client, Constants.INDEX_RULES);
            if (!rulesIndex.exists(ruleId)) {
                return new RestResponse(
                        Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
            }

            // Validate rule is in draft space
            String spaceValidationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_RULES, ruleId, Constants.KEY_RULE);
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus());
            }

            // 1. Call SAP to delete rule
            try {
                client
                        .execute(
                                WDeleteCustomRuleAction.INSTANCE,
                                new WDeleteCustomRuleRequest(
                                        ruleId, WriteRequest.RefreshPolicy.IMMEDIATE, true // forced
                                        ))
                        .actionGet();
            } catch (Exception e) {
                log.warn(
                        "Failed to delete rule [{}] from Security Analytics Plugin: {}",
                        ruleId,
                        e.getMessage());
            }

            // 2. Unlink from Integrations
            ContentUtils.unlinkResourceFromIntegrations(client, ruleId, Constants.KEY_RULES);

            // 3. Delete from CTI Rules Index
            rulesIndex.delete(ruleId);

            // Recalculate policy hashes for draft space
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(ruleId, RestStatus.OK.getStatus());

        } catch (Exception e) {
            log.error("Error deleting rule: {}", e.getMessage(), e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
