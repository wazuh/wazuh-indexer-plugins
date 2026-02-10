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
import java.util.Locale;
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
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * PUT /_plugins/content-manager/integrations/{id}
 *
 * <p>Updates an existing integration in the local engine.
 *
 * <p>Possible HTTP responses: - 200 OK: Integration updated successfully. - 400 Bad Request: Wazuh
 * Engine replied with an error response or invalid request. - 404 Not Found: Integration with
 * specified ID was not found. - 500 Internal Server Error: Unexpected error during processing.
 */
public class RestPutIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_update";

    private ContentIndex integrationsIndex;
    private PolicyHashService policyHashService;
    private SecurityAnalyticsService service;
    private final EngineService engine;
    private final Logger log = LogManager.getLogger(RestPutIntegrationAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private NodeClient nodeClient;

    /**
     * Constructs a new RestPutIntegrationAction.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPutIntegrationAction(EngineService engine) {
        this.engine = engine;
    }

    /**
     * Generate current date in YYYY-MM-DD format.
     *
     * @return String representing current date in YYYY-MM-DD format
     */
    public static String generateDate() {
        return LocalDate.now(TimeZone.getDefault().toZoneId()).toString();
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
                        .path(PluginSettings.INTEGRATIONS_URI + "/{id}")
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the REST request for updating an integration.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        request.param(Constants.KEY_ID);
        this.nodeClient = client;
        this.setPolicyHashService(new PolicyHashService(client));
        this.setIntegrationsContentIndex(new ContentIndex(client, Constants.INDEX_INTEGRATIONS, null));
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
     * Handles the incoming PUT integration request.
     *
     * @param request incoming request
     * @return a RestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public RestResponse handleRequest(RestRequest request) throws IOException {
        String id = request.param(Constants.KEY_ID);
        this.log.debug(
                "PUT integration request received (id={}, hasContent={}, uri={})",
                id,
                request.hasContent(),
                request.uri());

        // Check if ID is provided
        if (id == null || id.isEmpty()) {
            this.log.warn("Request rejected: integration ID is required");
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_FIELD_IS_REQUIRED, Constants.KEY_ID),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Validate UUID format
        try {
            java.util.UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INVALID_UUID, id),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Check if engine service exists
        if (this.engine == null || this.service == null) {
            this.log.error("Engine or Security Analytics service instance is null");
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Check request's payload exists
        if (!request.hasContent()) {
            this.log.warn("Request rejected: JSON request body missing");
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // Check request's payload is valid JSON
        JsonNode requestBody;
        try {
            requestBody = MAPPER.readTree(request.content().streamInput()).deepCopy();
        } catch (IOException ex) {
            this.log.warn("Request rejected: invalid JSON content", ex);
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // Verify request is of type "integration"
        if (!requestBody.has(Constants.KEY_TYPE)
                || !requestBody.get(Constants.KEY_TYPE).asText().equals(Constants.KEY_INTEGRATION)) {
            this.log.warn(
                    "Request rejected: invalid resource type (type={})",
                    requestBody.has(Constants.KEY_TYPE)
                            ? requestBody.get(Constants.KEY_TYPE).asText()
                            : null);
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INVALID_FIELD_FORMAT, Constants.KEY_TYPE),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Check that there is no ID field in the request body (ID comes from URL)
        if (!requestBody.at("/resource/id").isMissingNode()) {
            this.log.warn("Request rejected: id field present in request body");
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // Verify integration exists and is in draft space
        GetRequest getRequest = new GetRequest(Constants.INDEX_INTEGRATIONS, id);
        GetResponse getResponse;
        try {
            getResponse = this.nodeClient.get(getRequest).actionGet();
        } catch (Exception e) {
            this.log.error("Failed to retrieve existing integration (id={})", id, e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (!getResponse.isExists()) {
            this.log.warn("Request rejected: integration not found (id={})", id);
            return new RestResponse(Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
        }

        // Verify integration is in draft space
        Map<String, Object> existingSource = getResponse.getSourceAsMap();
        if (existingSource.containsKey(Constants.KEY_SPACE)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> space = (Map<String, Object>) existingSource.get(Constants.KEY_SPACE);
            String spaceName = (String) space.get(Constants.KEY_NAME);
            if (!Space.DRAFT.equals(spaceName)) {
                this.log.warn(
                        "Request rejected: cannot update integration in space '{}' (id={})", spaceName, id);
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_RESOURCE_NOT_IN_DRAFT, Constants.KEY_INTEGRATION, id),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        } else {
            this.log.warn("Request rejected: integration has undefined space (id={})", id);
            return new RestResponse(Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
        }

        // Extract /resource
        JsonNode resource = requestBody.at("/resource");
        if (!resource.isObject()) {
            this.log.warn(
                    "Request rejected: /resource is not an object (nodeType={})", resource.getNodeType());
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_FIELD_IS_REQUIRED, Constants.KEY_RESOURCE),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Insert ID from URL
        ((ObjectNode) resource).put(Constants.KEY_ID, id);

        // Insert modification date
        String currentDate = RestPutIntegrationAction.generateDate();
        ((ObjectNode) resource).put(Constants.KEY_MODIFIED, currentDate);

        // Check if date is present in existing document to preserve it
        String createdDate = null;
        JsonNode existingDoc = this.integrationsIndex.getDocument(id);
        if (existingDoc != null && existingDoc.has(Constants.KEY_DOCUMENT)) {
            JsonNode doc = existingDoc.get(Constants.KEY_DOCUMENT);
            if (doc.has(Constants.KEY_DATE)) {
                createdDate = doc.get(Constants.KEY_DATE).asText();
            } else {
                createdDate = RestPutIntegrationAction.generateDate();
            }
        }

        // Remove date field if present
        ((ObjectNode) resource).put(Constants.KEY_DATE, createdDate);

        // Check if enabled is set (if it's not, preserve existing value or set to true by default)
        if (!resource.has(Constants.KEY_ENABLED)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> existingDocument =
                    (Map<String, Object>) existingSource.get(Constants.KEY_DOCUMENT);
            if (existingDocument != null && existingDocument.containsKey(Constants.KEY_ENABLED)) {
                ((ObjectNode) resource)
                        .put(Constants.KEY_ENABLED, (Boolean) existingDocument.get(Constants.KEY_ENABLED));
            } else {
                ((ObjectNode) resource).put(Constants.KEY_ENABLED, true);
            }
        }

        // Insert "draft" into /resource/space/name
        ((ObjectNode) requestBody)
                .putObject(Constants.KEY_SPACE)
                .put(Constants.KEY_NAME, Space.DRAFT.toString());

        // Calculate and add a hash to the integration
        String hash = HashCalculator.sha256(resource.toString());
        ((ObjectNode) requestBody).putObject(Constants.KEY_HASH).put(Constants.KEY_SHA256, hash);
        this.log.debug(
                "Computed integration sha256 hash for id={} (hashPrefix={})",
                id,
                hash.length() >= 12 ? hash.substring(0, 12) : hash);

        // Update integration in SAP (put the contents of "resource" inside Constants.KEY_DOCUMENT key)
        this.log.debug("Updating integration in Security Analytics (id={})", id);
        this.service.upsertIntegration(
                this.toJsonObject(MAPPER.createObjectNode().set(Constants.KEY_DOCUMENT, resource)),
                Space.DRAFT,
                PUT);

        // Construct engine validation payload
        this.log.debug("Validating integration with Engine (id={})", id);
        ObjectNode enginePayload = MAPPER.createObjectNode();
        enginePayload.set(Constants.KEY_RESOURCE, resource);
        enginePayload.put(Constants.KEY_TYPE, Constants.KEY_INTEGRATION);

        // Validate integration with Wazuh Engine
        final RestResponse validationResponse = this.engine.validate(enginePayload);

        try {
            MAPPER.readTree(validationResponse.getMessage()).isObject();
        } catch (Exception e) {
            this.log.error(
                    "Engine validation failed (id={}, status={}); SAP update may be inconsistent",
                    id,
                    validationResponse.getStatus());
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // If validation failed, return error (SAP was already updated, may need manual reconciliation)
        if (validationResponse.getStatus() != RestStatus.OK.getStatus()) {
            this.log.error(
                    "Engine validation failed (id={}, status={})", id, validationResponse.getStatus());
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        try {
            this.log.debug(
                    "Indexing updated integration into {} (id={})", Constants.INDEX_INTEGRATIONS, id);
            ObjectNode integrationsIndexPayload = MAPPER.createObjectNode();
            integrationsIndexPayload.set(Constants.KEY_DOCUMENT, resource);
            integrationsIndexPayload
                    .putObject(Constants.KEY_SPACE)
                    .put(Constants.KEY_NAME, Space.DRAFT.toString());
            IndexResponse integrationIndexResponse =
                    this.integrationsIndex.create(id, integrationsIndexPayload);

            // Check indexing response. We are expecting for a 200 OK status for update.
            if (integrationIndexResponse == null
                    || (integrationIndexResponse.status() != RestStatus.OK
                            && integrationIndexResponse.status() != RestStatus.CREATED)) {
                this.log.error(
                        "Indexing integration failed (id={}, status={})",
                        id,
                        integrationIndexResponse != null ? integrationIndexResponse.status() : null);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Update the space's hash in the policy
            this.log.debug(
                    "Recalculating space hash for draft space after integration update (id={})", id);

            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            this.log.info("Integration updated successfully (id={})", id);
            return new RestResponse(id, RestStatus.OK.getStatus());
        } catch (Exception e) {
            this.log.error("Unexpected error updating integration (id={})", id, e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    private JsonObject toJsonObject(JsonNode jsonNode) {
        return JsonParser.parseString(jsonNode.toString()).getAsJsonObject();
    }
}
