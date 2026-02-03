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
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

public class RestPostIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_create";

    private ContentIndex integrationsIndex;
    private ContentIndex policiesIndex;
    private PolicyHashService policyHashService;
    private SecurityAnalyticsService service;
    private final EngineService engine;
    private final Logger log = LogManager.getLogger(RestPostIntegrationAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_DECODERS_INDEX = ".cti-decoders";
    private static final String CTI_KVDBS_INDEX = ".cti-kvdbs";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";
    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String DRAFT_SPACE_NAME = "draft";

    public RestPostIntegrationAction(EngineService engine) {
        this.engine = engine;
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
        this.setPolicyHashService(new PolicyHashService(client));
        this.setIntegrationsContentIndex(new ContentIndex(client, CTI_INTEGRATIONS_INDEX, null));
        this.setPoliciesContentIndex(new ContentIndex(client, CTI_POLICIES_INDEX, null));
        this.setSecurityAnalyticsService(new SecurityAnalyticsServiceImpl(client));
        return channel -> channel.sendResponse(this.handleRequest(request).toBytesRestResponse());
    }

    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    public void setIntegrationsContentIndex(ContentIndex integrationsIndex) {
        this.integrationsIndex = integrationsIndex;
    }

    public void setPoliciesContentIndex(ContentIndex policiesIndex) {
        this.policiesIndex = policiesIndex;
    }

    public void setSecurityAnalyticsService(SecurityAnalyticsService service) {
        this.service = service;
    }

    public RestResponse handleRequest(RestRequest request) throws IOException {
        this.log.debug(
                "POST integration request received (hasContent={}, uri={})",
                request.hasContent(),
                request.uri());

        if (this.engine == null) {
            this.log.error("Engine instance is null");
            return new RestResponse(
                    "Engine instance is null.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (this.service == null) {
            this.log.error("Security Analytics service instance is null");
            return new RestResponse(
                    "Security Analytics service instance is null.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (!request.hasContent()) {
            this.log.warn("Request rejected: JSON request body missing");
            return new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        JsonNode requestBody;
        try {
            requestBody = MAPPER.readTree(request.content().streamInput()).deepCopy();
        } catch (IOException ex) {
            this.log.warn("Request rejected: invalid JSON content", ex);
            return new RestResponse("Invalid JSON content.", RestStatus.BAD_REQUEST.getStatus());
        }

        if (!requestBody.has("type") || !requestBody.get("type").asText().equals("integration")) {
            this.log.warn(
                    "Request rejected: invalid resource type (type={})",
                    requestBody.has("type") ? requestBody.get("type").asText() : null);
            return new RestResponse("Invalid resource type.", RestStatus.BAD_REQUEST.getStatus());
        }

        if (!requestBody.at("/resource/id").isMissingNode()) {
            this.log.warn("Request rejected: id field present in request body");
            return new RestResponse(
                    "ID field is not allowed in the request body.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Generate ID (no prefix)
        String id = this.generateId();

        JsonNode resource = requestBody.at("/resource");
        if (!resource.isObject()) {
            this.log.warn(
                    "Request rejected: /resource is not an object (nodeType={})", resource.getNodeType());
            return new RestResponse(
                    "Invalid JSON structure: /resource must be an object.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        ((ObjectNode) resource).put("id", id);

        String currentDate = RestPutIntegrationAction.generateDate();
        ((ObjectNode) resource).put("date", currentDate);
        ((ObjectNode) resource).put("modified", currentDate);

        if (!resource.has("enabled")) {
            ((ObjectNode) resource).put("enabled", true);
        }

        ((ObjectNode) requestBody).putObject("space").put("name", DRAFT_SPACE_NAME);

        ((ObjectNode) resource).set("rules", MAPPER.createArrayNode());
        ((ObjectNode) resource).set("decoders", MAPPER.createArrayNode());
        ((ObjectNode) resource).set("kvdbs", MAPPER.createArrayNode());

        String hash = HashCalculator.sha256(resource.toString());
        ((ObjectNode) requestBody).putObject("hash").put("sha256", hash);
        this.log.debug(
                "Computed integration sha256 hash for id={} (hashPrefix={})",
                id,
                hash.length() >= 12 ? hash.substring(0, 12) : hash);

        this.log.debug("Creating/upserting integration in Security Analytics (id={})", id);
        this.service.upsertIntegration(
                this.toJsonObject(MAPPER.createObjectNode().set("document", resource)), Space.DRAFT, POST);

        this.log.debug("Validating integration with Engine (id={})", id);
        ObjectNode enginePayload = MAPPER.createObjectNode();
        enginePayload.set("resource", resource);
        enginePayload.put("type", "integration");

        final RestResponse validationResponse = this.engine.validate(enginePayload);

        try {
            MAPPER.readTree(validationResponse.getMessage()).isObject();
        } catch (Exception e) {
            this.log.error(
                    "Engine validation failed (id={}, status={}); rolling back SAP integration",
                    id,
                    validationResponse.getStatus());
            this.service.deleteIntegration(id);
            return new RestResponse(
                    "Failed to create Integration, Invalid validation response: "
                            + validationResponse.getMessage()
                            + ".",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (validationResponse.getStatus() != RestStatus.OK.getStatus()) {
            this.log.error(
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

        try {
            this.log.debug("Indexing integration into {} (id={})", CTI_INTEGRATIONS_INDEX, id);
            ObjectNode integrationsIndexPayload = MAPPER.createObjectNode();
            integrationsIndexPayload.set("document", resource);
            integrationsIndexPayload.putObject("space").put("name", DRAFT_SPACE_NAME);
            // Use UUID as document ID (no prefix)
            IndexResponse integrationIndexResponse =
                    this.integrationsIndex.create(id, integrationsIndexPayload);

            if (integrationIndexResponse == null
                    || integrationIndexResponse.status() != RestStatus.CREATED) {
                this.log.error(
                        "Indexing integration failed (id={}, status={}); rolling back SAP integration",
                        id,
                        integrationIndexResponse != null ? integrationIndexResponse.status() : null);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to index integration.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            this.log.debug(
                    "Searching for draft policy in {} (space={})", CTI_POLICIES_INDEX, DRAFT_SPACE_NAME);
            TermQueryBuilder queryBuilder = new TermQueryBuilder("space.name", DRAFT_SPACE_NAME);

            JsonObject draftPolicyHit;
            JsonNode draftPolicy;
            String draftPolicyId;

            try {
                JsonObject searchResult = this.policiesIndex.searchByQuery(queryBuilder);
                if (searchResult == null
                        || !searchResult.has("hits")
                        || searchResult.getAsJsonArray("hits").isEmpty()) {
                    throw new IllegalStateException("No hits found");
                }
                JsonArray hitsArray = searchResult.getAsJsonArray("hits");
                draftPolicyHit = hitsArray.get(0).getAsJsonObject();
                draftPolicyId = draftPolicyHit.get("id").getAsString();
                draftPolicy = MAPPER.readTree(draftPolicyHit.toString());
            } catch (Exception e) {
                this.log.error("Draft policy search returned null result; rolling back (id={})", id);
                this.integrationsIndex.delete(id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Draft policy not found.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            JsonNode draftPolicyDocument = draftPolicy.at("/document");
            if (draftPolicyDocument.isMissingNode()) {
                this.log.error(
                        "Draft policy hit missing /document (policyId={}), rolling back (id={})",
                        draftPolicyId,
                        id);
                this.integrationsIndex.delete(id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to retrieve draft policy document.",
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            this.log.debug("Draft policy found (policyId={}); updating integrations", draftPolicyId);

            ArrayNode draftPolicyIntegrations = (ArrayNode) draftPolicyDocument.get("integrations");
            if (draftPolicyIntegrations == null || !draftPolicyIntegrations.isArray()) {
                this.log.error(
                        "Draft policy integrations field missing or not array (policyId={}); rolling back SAP integration (id={})",
                        draftPolicyId,
                        id);
                this.integrationsIndex.delete(id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        "Failed to retrieve integrations array from draft policy document.",
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Add the new integration ID to the integrations array
            draftPolicyIntegrations.add(id);

            String draftPolicyHash = HashCalculator.sha256(draftPolicyDocument.asText());
            ((ObjectNode) draftPolicy.at("/hash")).put("sha256", draftPolicyHash);
            this.log.debug(
                    "Updated draft policy hash (policyId={}, hashPrefix={})",
                    draftPolicyId,
                    draftPolicyHash.length() >= 12 ? draftPolicyHash.substring(0, 12) : draftPolicyHash);

            this.log.debug(
                    "Indexing updated draft policy into {} (policyId={})", CTI_POLICIES_INDEX, draftPolicyId);
            IndexResponse indexDraftPolicyResponse =
                    this.policiesIndex.create(draftPolicyId, draftPolicy);

            if (indexDraftPolicyResponse == null || indexDraftPolicyResponse.status() != RestStatus.OK) {
                this.log.error(
                        "Indexing updated draft policy failed (policyId={}, status={}); rolling back SAP integration (id={})",
                        draftPolicyId,
                        indexDraftPolicyResponse != null ? indexDraftPolicyResponse.status() : null,
                        id);
                this.service.deleteIntegration(id);
                this.integrationsIndex.delete(id);
                return new RestResponse(
                        "Failed to update draft policy.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

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
                    "Integration created successfully with ID: " + id, RestStatus.CREATED.getStatus());
        } catch (Exception e) {
            this.log.error(
                    "Unexpected error creating integration (id={}); rolling back SAP integration", id, e);
            this.service.deleteIntegration(id);
            return new RestResponse(
                    "Unexpected error during processing.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    public String generateId() {
        return UUID.randomUUID().toString();
    }

    private JsonObject toJsonObject(JsonNode jsonNode) {
        return JsonParser.parseString(jsonNode.toString()).getAsJsonObject();
    }
}
