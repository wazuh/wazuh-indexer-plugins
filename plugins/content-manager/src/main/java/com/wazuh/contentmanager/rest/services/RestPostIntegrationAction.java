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

import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.UUIDs;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * TODO !CHANGE_ME POST /_plugins/content-manager/integrations
 *
 * <p>Creates an integration in the local engine.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestPostIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_create";

    /**
     * @TODO: To be deleted. This needs to be retrieved from a single source of truth.
     */
    private static final String CTI_DECODERS_INDEX = ".cti-decoders";

    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_KVDBS_INDEX = ".cti-kvdbs";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";
    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String DRAFT_SPACE_NAME = "draft";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private ContentIndex integrationsIndex;
    private ContentIndex policiesIndex;

    private final EngineService engine;
    private final SecurityAnalyticsService service;

    private final Logger log = LogManager.getLogger(RestPostIntegrationAction.class);
    private PolicyHashService policyHashService;

    /**
     * Constructs a new TODO !CHANGE_ME.
     *
     * @param engine The service instance to communicate with the local engine service.
     * @param service The service instance to communicate with the security analytics service.
     */
    public RestPostIntegrationAction(EngineService engine, SecurityAnalyticsService service) {
        this.service = service;
        this.engine = engine;
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
                        .path(PluginSettings.INTEGRATIONS_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        this.policyHashService = new PolicyHashService(client);
        this.integrationsIndex = new ContentIndex(client, CTI_INTEGRATIONS_INDEX, null);
        this.policiesIndex = new ContentIndex(client, CTI_POLICIES_INDEX, null);
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
     * @param policiesIndex the integrations index ContentIndex object
     */
    public void setPoliciesContentIndex(ContentIndex policiesIndex) {
        this.policiesIndex = policiesIndex;
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request incoming request
     * @return a RestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public RestResponse handleRequest(RestRequest request) throws IOException {
        this.log.debug(
                "POST integration request received (hasContent={}, uri={})",
                request.hasContent(),
                request.uri());

        // Check if engine service exists
        if (this.engine == null) {
            this.log.error("Engine instance is null");
            return new RestResponse(
                    "Engine instance is null.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Check if security analytics service exists
        if (this.service == null) {
            this.log.error("Security Analytics service instance is null");
            return new RestResponse(
                    "Security Analytics service instance is null.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Check request's payload exists
        if (!request.hasContent()) {
            this.log.warn("Request rejected: JSON request body missing");
            return new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Check request's payload is valid JSON
        JsonNode requestPayload;
        try {
            requestPayload = MAPPER.readTree(request.content().streamInput());
        } catch (IOException ex) {
            this.log.warn("Request rejected: invalid JSON content", ex);
            return new RestResponse("Invalid JSON content.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Verify request is of type "integration"
        if (!requestPayload.has("type") || !requestPayload.get("type").asText().equals("integration")) {
            this.log.warn(
                    "Request rejected: invalid request type (type={})",
                    requestPayload.has("type") ? requestPayload.get("type").asText() : null);
            return new RestResponse("Invalid request type.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Check that there is no ID field
        if (!requestPayload.at("/resource/document/id").isMissingNode()) {
            this.log.warn("Request rejected: id field present in request body");
            return new RestResponse(
                    "ID field is not allowed in the request body.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Generate ID
        String id = this.generateId();
        this.log.debug("Generated integration id={}", id);

        // Extract /resource and /resource/document nodes
        JsonNode integrationNode = requestPayload.at("/resource");
        final JsonNode documentNode = requestPayload.at("/resource/document");
        if (!documentNode.isObject()) {
            this.log.warn(
                    "Request rejected: /resource/document is not an object (nodeType={})",
                    documentNode.getNodeType());
            return new RestResponse(
                    "Invalid JSON structure: /resource/document must be an object.",
                    RestStatus.BAD_REQUEST.getStatus());
        }
        final ObjectNode documentObject = (ObjectNode) documentNode;

        // Insert ID into /document/id
        documentObject.put("id", id);

        // Insert "draft" into /resource/document/space/name
        documentObject.putObject("space").put("name", DRAFT_SPACE_NAME);

        // Calculate and add a hash to the integration
        String hash = HashCalculator.sha256(documentNode.toString());
        ((ObjectNode) integrationNode).putObject("hash").put("sha256", hash);
        this.log.debug(
                "Computed integration sha256 hash for id={} (hashPrefix={})",
                id,
                hash.length() >= 12 ? hash.substring(0, 12) : hash);

        // Create integration in SAP
        this.log.debug("Creating/upserting integration in Security Analytics (id={})", id);
        final WIndexIntegrationResponse sapResponse = this.service.upsertIntegration(requestPayload);

        // Check if SAP response is valid
        if (sapResponse == null || sapResponse.getStatus() == null) {
            this.log.error("SAP upsert integration failed: response/status is null (id={})", id);
            return new RestResponse(
                    "Failed to create Integration, SAP response is null.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // If SAP response is not OK, return error
        if (sapResponse.getStatus() != RestStatus.OK) {
            this.log.warn(
                    "SAP upsert integration returned non-OK status={} (id={})", sapResponse.getStatus(), id);
            return new RestResponse(
                    "Failed to create Integration, SAP response: " + sapResponse.getStatus(),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Validate integration with Wazuh Engine
        this.log.debug("Validating integration with Engine (id={})", id);
        final RestResponse validationResponse = this.engine.validate(requestPayload);

        // If validation failed, delete the created integration in SAP
        if (validationResponse.getStatus() != RestStatus.OK.getStatus()) {
            this.log.warn(
                    "Engine validation failed (id={}, status={}); rolling back SAP integration",
                    id,
                    validationResponse.getStatus());
            this.service.deleteIntegration(id);
            return new RestResponse(
                    "Failed to create Integration, Validation response: "
                            + validationResponse.getStatus()
                            + ".",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // From here on, we should roll back SAP integration on any error to avoid partial state.
        try {
            // Index the integration into CTI integrations index (sync + check response)
            this.log.debug("Indexing integration into {} (id={})", CTI_INTEGRATIONS_INDEX, id);
            IndexResponse integrationIndexResponse = this.integrationsIndex.create(id, integrationNode);

            // Check indexing response. We are expecting for a 200 OK status.
            if (integrationIndexResponse == null || integrationIndexResponse.status() != RestStatus.OK) {
                this.log.error(
                        "Indexing integration failed (id={}, status={}); rolling back SAP integration",
                        id,
                        integrationIndexResponse != null ? integrationIndexResponse.status() : null);
                // otherwise, we delete the created SAP integration and return an error.
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to index integration.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Search for the draft policy (scoped to policies index, limit 1)
            this.log.debug(
                    "Searching for draft policy in {} (space={})", CTI_POLICIES_INDEX, DRAFT_SPACE_NAME);
            TermQueryBuilder queryBuilder = new TermQueryBuilder("document.space.name", DRAFT_SPACE_NAME);
            JsonObject searchResult = this.policiesIndex.searchByQuery(queryBuilder);

            if (searchResult == null) {
                this.log.error("Draft policy search returned null result; rolling back (id={})", id);
                // Rollback: delete created integration in CTI index and in SAP
                this.integrationsIndex.delete(id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Draft policy not found.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }
            JsonNode draftPolicy = MAPPER.readTree(searchResult.toString());

            // If we cannot find the draft space policy, rollback and return an error.
            if (draftPolicy == null) {
                this.log.error("Draft policy not found; rolling back (id={})", id);
                // Rollback: delete created integration in CTI index and in SAP
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Draft policy not found.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Get the policy document
            JsonNode draftPolicyNode = draftPolicy.get("hits").get(0);

            // Get the policy Id
            String policyId = draftPolicyNode.get("_id").asText();

            JsonNode documentJsonObject = draftPolicyNode.at("/_source/document");
            if (documentJsonObject.isMissingNode()) {
                this.log.error("Draft policy hit missing /_source/document (policyId={})", policyId);
                return new RestResponse(
                        "Failed to retrieve draft policy document.",
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            //   String policyId = searchResponse.getHits().getAt(0).getId();
            this.log.debug("Draft policy found (policyId={}); updating integrations", policyId);

            // Retrieve the integrations array from the policy document
            ArrayNode integrationsArray = (ArrayNode) documentJsonObject.get("integrations");
            if (integrationsArray == null || !integrationsArray.isArray()) {
                this.log.error(
                        "Draft policy integrations field missing or not array (policyId={}); rolling back SAP integration (id={})",
                        policyId,
                        id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to retrieve integrations array from draft policy document.",
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Add the new integration ID to the integrations array (avoid duplicates)
            for (JsonNode existing : integrationsArray) {
                if (id.equals(existing.asText())) {
                    // Integration ID already exists in the policy
                    this.log.warn(
                            "Integration id already exists in draft policy (policyId={}, id={}); rolling back SAP integration",
                            policyId,
                            id);
                    this.service.deleteIntegration(id);
                    return new RestResponse(
                            "Integration ID already exists in the draft policy.",
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                }
            }
            integrationsArray.add(id);

            // Update the policies own hash
            String policyHash = HashCalculator.sha256(documentJsonObject.asText());

            // Put policyHash inside hash.sha256 key
            ((ObjectNode) draftPolicyNode.at("/_source/hash")).put("sha256", policyHash);
            this.log.debug(
                    "Updated draft policy hash (policyId={}, hashPrefix={})",
                    policyId,
                    policyHash.length() >= 12 ? policyHash.substring(0, 12) : policyHash);

            // Index the policy with the updated integrations array
            this.log.debug(
                    "Indexing updated draft policy into {} (policyId={})", CTI_POLICIES_INDEX, policyId);
            IndexResponse indexPolicyResponse = this.policiesIndex.create(policyId, draftPolicyNode);

            if (indexPolicyResponse == null || indexPolicyResponse.status() != RestStatus.OK) {
                this.log.error(
                        "Indexing updated draft policy failed (policyId={}, status={}); rolling back SAP integration (id={})",
                        policyId,
                        indexPolicyResponse != null ? indexPolicyResponse.status() : null,
                        id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to update draft policy.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Update the space's hash in the policy
            this.log.debug(
                    "Recalculating space hash for draft space after integration create (id={})", id);

            this.policyHashService.calculateAndUpdate(
                    CTI_POLICIES_INDEX,
                    CTI_INTEGRATIONS_INDEX,
                    CTI_DECODERS_INDEX,
                    CTI_KVDBS_INDEX,
                    CTI_RULES_INDEX,
                    List.of(Space.DRAFT.toString()));

            this.log.info("Integration created successfully (id={})", id);
            return new RestResponse(
                    "Integration created successfully with ID: " + id + ".", RestStatus.OK.getStatus());
        } catch (Exception e) {
            this.log.error(
                    "Unexpected error creating integration (id={}); rolling back SAP integration", id, e);
            this.service.deleteIntegration(id);
            return new RestResponse(
                    "Unexpected error during processing.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Generates a unique identifier for an integration.
     *
     * @return a unique integration ID string
     */
    public String generateId() {
        return "d_" + UUIDs.base64UUID();
    }
}
