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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/content-manager/integrations/{id}
 *
 * <p>Deletes an existing integration from the draft space.
 *
 * <p>Possible HTTP responses: - 200 OK: Integration deleted successfully. - 400 Bad Request:
 * Integration is not in draft space or other validation error. - 404 Not Found: Integration with
 * specified ID was not found. - 500 Internal Server Error: Unexpected error during processing.
 */
public class RestDeleteIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_delete";

    private ContentIndex integrationsIndex;
    private ContentIndex policiesIndex;
    private PolicyHashService policyHashService;
    private SecurityAnalyticsService service;
    private final Logger log = LogManager.getLogger(RestDeleteIntegrationAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private NodeClient nodeClient;

    /**
     * Constructs a new RestDeleteIntegrationAction.
     *
     * <p>Note: The engine parameter is kept for API compatibility with other integration actions but
     * is not used for delete operations.
     *
     * @param engine The engine service (unused in delete operations).
     */
    @SuppressWarnings("unused")
    public RestDeleteIntegrationAction(
            @SuppressWarnings("unused") com.wazuh.contentmanager.engine.services.EngineService engine) {}

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

    /**
     * Prepares the REST request for deleting an integration.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the delete operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        request.param(Constants.KEY_ID);
        this.nodeClient = client;
        this.setPolicyHashService(new PolicyHashService(client));
        this.setIntegrationsContentIndex(new ContentIndex(client, Constants.INDEX_INTEGRATIONS, null));
        this.setPoliciesContentIndex(new ContentIndex(client, Constants.INDEX_POLICIES, null));
        this.setSecurityAnalyticsService(new SecurityAnalyticsServiceImpl(client));
        return channel -> channel.sendResponse(this.handleRequest(request).toBytesRestResponse());
    }

    /**
     * @param policyHashService the policy hash service to set
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    /**
     * Setter for the integrations index, used in tests.
     *
     * @param integrationsIndex the integrations index ContentIndex object
     */
    public void setIntegrationsContentIndex(ContentIndex integrationsIndex) {
        this.integrationsIndex = integrationsIndex;
    }

    /**
     * Setter for the policies index, used in tests.
     *
     * @param policiesIndex the policies index ContentIndex object
     */
    public void setPoliciesContentIndex(ContentIndex policiesIndex) {
        this.policiesIndex = policiesIndex;
    }

    /**
     * @param service the security analytics service to set
     */
    public void setSecurityAnalyticsService(SecurityAnalyticsService service) {
        this.service = service;
    }

    /**
     * Setter for the node client, used in tests.
     *
     * @param nodeClient the node client to set
     */
    public void setNodeClient(NodeClient nodeClient) {
        this.nodeClient = nodeClient;
    }

    /**
     * Handles the incoming DELETE integration request.
     *
     * @param request incoming request
     * @return a RestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public RestResponse handleRequest(RestRequest request) throws IOException {
        String id = request.param(Constants.KEY_ID);
        this.log.debug("DELETE integration request received (id={}, uri={})", id, request.uri());

        // Check if ID is provided
        RestResponse validationError = DocumentValidations.validateRequiredParam(id, Constants.KEY_ID);
        if (validationError != null) {
            return validationError;
        }

        // Validate UUID format
        validationError = DocumentValidations.validateUUID(id);
        if (validationError != null) {
            return validationError;
        }

        // Check if security analytics service exists
        if (this.service == null) {
            this.log.error("Security Analytics service not initialized");
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Verify integration exists and is in draft space
        GetRequest getRequest = new GetRequest(Constants.INDEX_INTEGRATIONS, id);
        GetResponse getResponse;
        try {
            getResponse = this.nodeClient.get(getRequest).actionGet();
        } catch (Exception e) {
            this.log.error("Failed to retrieve existing integration (id={}): {}", id, e.getMessage(), e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (!getResponse.isExists()) {
            return new RestResponse(Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
        }

        // Verify integration is in draft space
        Map<String, Object> existingSource = getResponse.getSourceAsMap();
        if (existingSource.containsKey(Constants.KEY_SPACE)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> space = (Map<String, Object>) existingSource.get(Constants.KEY_SPACE);
            String spaceName = (String) space.get(Constants.KEY_NAME);
            if (!Space.DRAFT.equals(spaceName)) {
                return new RestResponse(
                        String.format(Constants.E_400_RESOURCE_NOT_IN_DRAFT, Constants.KEY_INTEGRATION, id),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        } else {
            return new RestResponse(Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
        }

        // Check for dependent resources
        if (existingSource.containsKey(Constants.KEY_DOCUMENT)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> document =
                    (Map<String, Object>) existingSource.get(Constants.KEY_DOCUMENT);

            if (this.isListNotEmpty(document.get(Constants.KEY_DECODERS))) {
                return new RestResponse(
                        String.format(Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_DECODERS),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            if (this.isListNotEmpty(document.get(Constants.KEY_RULES))) {
                return new RestResponse(
                        String.format(Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_RULES),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            if (this.isListNotEmpty(document.get(Constants.KEY_KVDBS))) {
                return new RestResponse(
                        String.format(Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_KVDBS),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        }

        try {
            // Delete integration from Security Analytics Plugin
            this.log.debug("Deleting integration from Security Analytics (id={})", id);
            try {
                this.service.deleteIntegration(id);
            } catch (Exception e) {
                this.log.warn(
                        "Failed to delete integration [{}] from Security Analytics Plugin: {}",
                        id,
                        e.getMessage());
            }

            // Delete from CTI integrations index
            this.log.debug("Deleting integration from {} (id={})", Constants.INDEX_INTEGRATIONS, id);
            this.integrationsIndex.delete(id);

            // Search for the draft policy to remove the integration ID from its integrations array
            this.log.debug(
                    "Searching for draft policy in {} (space={})", Constants.INDEX_POLICIES, Space.DRAFT);
            TermQueryBuilder queryBuilder = new TermQueryBuilder(Constants.Q_SPACE_NAME, Space.DRAFT);

            JsonObject draftPolicyHit;
            JsonNode draftPolicy;
            String draftPolicyId;

            try {
                JsonObject searchResult = this.policiesIndex.searchByQuery(queryBuilder);
                if (searchResult == null
                        || !searchResult.has(Constants.Q_HITS)
                        || searchResult.getAsJsonArray(Constants.Q_HITS).isEmpty()) {
                    throw new IllegalStateException("No hits found");
                }
                JsonArray hitsArray = searchResult.getAsJsonArray(Constants.Q_HITS);
                draftPolicyHit = hitsArray.get(0).getAsJsonObject();
                draftPolicyId = draftPolicyHit.get(Constants.KEY_ID).getAsString();
                draftPolicy = MAPPER.readTree(draftPolicyHit.toString());
            } catch (Exception e) {
                this.log.error("Draft policy search failed (id={}): {}", id, e.getMessage(), e);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            JsonNode draftPolicyDocument = draftPolicy.at("/document");
            if (draftPolicyDocument.isMissingNode()) {
                this.log.error(
                        "Draft policy hit missing /document (policyId={}), (id={})", draftPolicyId, id);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            this.log.debug(
                    "Draft policy found (policyId={}); removing integration from array", draftPolicyId);

            // Retrieve the integrations array from the policy document
            ArrayNode draftPolicyIntegrations =
                    (ArrayNode) draftPolicyDocument.get(Constants.KEY_INTEGRATIONS);
            if (draftPolicyIntegrations == null || !draftPolicyIntegrations.isArray()) {
                this.log.error(
                        "Draft policy integrations field missing or not array (policyId={}); (id={})",
                        draftPolicyId,
                        id);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Remove the integration ID from the integrations array
            ArrayNode updatedIntegrations = MAPPER.createArrayNode();
            for (JsonNode integrationId : draftPolicyIntegrations) {
                if (!integrationId.asText().equals(id)) {
                    updatedIntegrations.add(integrationId);
                }
            }
            ((ObjectNode) draftPolicyDocument).set(Constants.KEY_INTEGRATIONS, updatedIntegrations);

            // Update the policy's own hash
            String draftPolicyHash = HashCalculator.sha256(draftPolicyDocument.asText());

            // Put policyHash inside hash.sha256 key
            ((ObjectNode) draftPolicy.at("/hash")).put("sha256", draftPolicyHash);
            this.log.debug(
                    "Updated draft policy hash (policyId={}, hashPrefix={})",
                    draftPolicyId,
                    draftPolicyHash.length() >= 12 ? draftPolicyHash.substring(0, 12) : draftPolicyHash);

            // Index the policy with the updated integrations array
            this.log.debug(
                    "Indexing updated draft policy into {} (policyId={})",
                    Constants.INDEX_POLICIES,
                    draftPolicyId);
            IndexResponse indexDraftPolicyResponse =
                    this.policiesIndex.create(draftPolicyId, draftPolicy);

            if (indexDraftPolicyResponse == null || indexDraftPolicyResponse.status() != RestStatus.OK) {
                this.log.error(
                        "Indexing updated draft policy failed (policyId={}, status={}); (id={})",
                        draftPolicyId,
                        indexDraftPolicyResponse != null ? indexDraftPolicyResponse.status() : null,
                        id);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Update the space's hash in the policy
            this.log.debug(
                    "Recalculating space hash for draft space after integration deletion (id={})", id);

            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(id, RestStatus.OK.getStatus());
        } catch (Exception e) {
            this.log.error("Error deleting integration: {}", e.getMessage(), e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Checks if an object is a non-empty list.
     *
     * @param obj The object to check.
     * @return true if the object is a List and is not empty, false otherwise.
     */
    private boolean isListNotEmpty(Object obj) {
        return obj instanceof List && !((List<?>) obj).isEmpty();
    }
}
