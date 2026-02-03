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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.PUT;

public class RestPutIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_update";

    private ContentIndex integrationsIndex;
    private PolicyHashService policyHashService;
    private SecurityAnalyticsService service;
    private final EngineService engine;
    private final Logger log = LogManager.getLogger(RestPutIntegrationAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CTI_DECODERS_INDEX = ".cti-decoders";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_KVDBS_INDEX = ".cti-kvdbs";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";
    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String DRAFT_SPACE_NAME = "draft";

    private NodeClient nodeClient;

    public RestPutIntegrationAction(EngineService engine) {
        this.engine = engine;
    }

    public static String generateDate() {
        return LocalDate.now(TimeZone.getDefault().toZoneId()).toString();
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.INTEGRATIONS_URI + "/{id}")
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        request.param("id");
        this.nodeClient = client;
        this.setPolicyHashService(new PolicyHashService(client));
        this.setIntegrationsContentIndex(new ContentIndex(client, CTI_INTEGRATIONS_INDEX, null));
        this.setSecurityAnalyticsService(new SecurityAnalyticsServiceImpl(client));
        return channel -> channel.sendResponse(this.handleRequest(request).toBytesRestResponse());
    }

    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    public void setIntegrationsContentIndex(ContentIndex integrationsIndex) {
        this.integrationsIndex = integrationsIndex;
    }

    public void setSecurityAnalyticsService(SecurityAnalyticsService service) {
        this.service = service;
    }

    public void setNodeClient(NodeClient nodeClient) {
        this.nodeClient = nodeClient;
    }

    public RestResponse handleRequest(RestRequest request) throws IOException {
        String id = request.param("id");
        this.log.debug(
                "PUT integration request received (id={}, hasContent={}, uri={})",
                id,
                request.hasContent(),
                request.uri());

        if (id == null || id.isEmpty()) {
            this.log.warn("Request rejected: integration ID is required");
            return new RestResponse("Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
        }

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
                    "ID field is not allowed in the request body. Use the URL path parameter instead.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        GetRequest getRequest = new GetRequest(CTI_INTEGRATIONS_INDEX, id);
        GetResponse getResponse;
        try {
            getResponse = this.nodeClient.get(getRequest).actionGet();
        } catch (Exception e) {
            this.log.error("Failed to retrieve existing integration (id={})", id, e);
            return new RestResponse(
                    "Failed to retrieve existing integration.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (!getResponse.isExists()) {
            this.log.warn("Request rejected: integration not found (id={})", id);
            return new RestResponse("Integration not found: " + id, RestStatus.NOT_FOUND.getStatus());
        }

        Map<String, Object> existingSource = getResponse.getSourceAsMap();
        if (existingSource.containsKey("space")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> space = (Map<String, Object>) existingSource.get("space");
            String spaceName = (String) space.get("name");
            if (!DRAFT_SPACE_NAME.equals(spaceName)) {
                this.log.warn(
                        "Request rejected: cannot update integration in space '{}' (id={})", spaceName, id);
                return new RestResponse(
                        "Cannot update integration from space '"
                                + spaceName
                                + "'. Only 'draft' space is modifiable.",
                        RestStatus.BAD_REQUEST.getStatus());
            }
        } else {
            this.log.warn("Request rejected: integration has undefined space (id={})", id);
            return new RestResponse(
                    "Cannot update integration with undefined space.", RestStatus.BAD_REQUEST.getStatus());
        }

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
        ((ObjectNode) resource).put("modified", currentDate);

        String createdDate = null;
        JsonNode existingDoc = this.integrationsIndex.getDocument(id);
        if (existingDoc != null && existingDoc.has("document")) {
            JsonNode doc = existingDoc.get("document");
            if (doc.has("date")) {
                createdDate = doc.get("date").asText();
            } else {
                createdDate = RestPutIntegrationAction.generateDate();
            }
        }

        ((ObjectNode) resource).put("date", createdDate);

        if (!resource.has("enabled")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> existingDocument = (Map<String, Object>) existingSource.get("document");
            if (existingDocument != null && existingDocument.containsKey("enabled")) {
                ((ObjectNode) resource).put("enabled", (Boolean) existingDocument.get("enabled"));
            } else {
                ((ObjectNode) resource).put("enabled", true);
            }
        }

        ((ObjectNode) requestBody).putObject("space").put("name", DRAFT_SPACE_NAME);

        String hash = HashCalculator.sha256(resource.toString());
        ((ObjectNode) requestBody).putObject("hash").put("sha256", hash);
        this.log.debug(
                "Computed integration sha256 hash for id={} (hashPrefix={})",
                id,
                hash.length() >= 12 ? hash.substring(0, 12) : hash);

        this.log.debug("Updating integration in Security Analytics (id={})", id);
        this.service.upsertIntegration(
                this.toJsonObject(MAPPER.createObjectNode().set("document", resource)), Space.DRAFT, PUT);

        this.log.debug("Validating integration with Engine (id={})", id);
        ObjectNode enginePayload = MAPPER.createObjectNode();
        enginePayload.set("resource", resource);
        enginePayload.put("type", "integration");

        final RestResponse validationResponse = this.engine.validate(enginePayload);

        try {
            MAPPER.readTree(validationResponse.getMessage()).isObject();
        } catch (Exception e) {
            this.log.error(
                    "Engine validation failed (id={}, status={}); SAP update may be inconsistent",
                    id,
                    validationResponse.getStatus());
            return new RestResponse(
                    "Failed to update Integration, Invalid validation response: "
                            + validationResponse.getMessage()
                            + ".",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (validationResponse.getStatus() != RestStatus.OK.getStatus()) {
            this.log.error(
                    "Engine validation failed (id={}, status={})", id, validationResponse.getStatus());
            return new RestResponse(
                    "Failed to update Integration, Validation response: "
                            + validationResponse.getStatus()
                            + ".",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        try {
            this.log.debug("Indexing updated integration into {} (id={})", CTI_INTEGRATIONS_INDEX, id);
            ObjectNode integrationsIndexPayload = MAPPER.createObjectNode();
            integrationsIndexPayload.set("document", resource);
            integrationsIndexPayload.putObject("space").put("name", DRAFT_SPACE_NAME);
            IndexResponse integrationIndexResponse =
                    this.integrationsIndex.create(id, integrationsIndexPayload);

            if (integrationIndexResponse == null
                    || (integrationIndexResponse.status() != RestStatus.OK
                            && integrationIndexResponse.status() != RestStatus.CREATED)) {
                this.log.error(
                        "Indexing integration failed (id={}, status={})",
                        id,
                        integrationIndexResponse != null ? integrationIndexResponse.status() : null);
                return new RestResponse(
                        "Failed to index integration.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            this.log.debug(
                    "Recalculating space hash for draft space after integration update (id={})", id);

            this.policyHashService.calculateAndUpdate(
                    CTI_POLICIES_INDEX,
                    CTI_INTEGRATIONS_INDEX,
                    CTI_DECODERS_INDEX,
                    CTI_KVDBS_INDEX,
                    CTI_RULES_INDEX,
                    List.of(Space.DRAFT.toString()));

            this.log.info("Integration updated successfully (id={})", id);
            return new RestResponse(
                    "Integration updated successfully with ID: " + id, RestStatus.OK.getStatus());
        } catch (Exception e) {
            this.log.error("Unexpected error updating integration (id={})", id, e);
            return new RestResponse(
                    "Unexpected error during processing.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    private JsonObject toJsonObject(JsonNode jsonNode) {
        return JsonParser.parseString(jsonNode.toString()).getAsJsonObject();
    }
}
