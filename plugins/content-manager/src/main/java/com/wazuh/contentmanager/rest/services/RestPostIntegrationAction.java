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

import com.fasterxml.jackson.annotation.ObjectIdGenerators.UUIDGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;
import java.util.UUID;
import org.opensearch.common.UUIDs;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * TODO !CHANGE_ME POST /_plugins/content-manager/integrations
 *
 * <p>Creates a integration in the local engine.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestPostIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_create";
    private final EngineService engine;
    private final SecurityAnalyticsService service;

    /**
     * Constructs a new TODO !CHANGE_ME.
     *
     * @param engine  The service instance to communicate with the local engine service.
     * @param service The service instance to communicate with the security analytics service.
     */
    public RestPostIntegrationAction(EngineService engine, SecurityAnalyticsService service) {
        this.service = service;
        this.engine = engine;
    }

    /**
     * Return a short identifier for this handler.
     */
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
     * @param client  the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
        throws IOException {
        return channel -> channel.sendResponse(this.handleRequest(request));
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request incoming request
     * @return a BytesRestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public RestResponse handleRequest(RestRequest request) throws IOException {
        // Check if engine service exists
        if (this.engine == null) {
            RestResponse error =
                new RestResponse(
                    "Engine instance is null.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent());
        }

        // Check request's payload exists
        if (!request.hasContent()) {
            RestResponse error =
                new RestResponse("JSON request body is required.",
                    RestStatus.BAD_REQUEST.getStatus());
            return new BytesRestResponse(RestStatus.BAD_REQUEST, error.toXContent());
        }

        // Check request's payload is valid JSON
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = mapper.readTree(request.content().streamInput());
        } catch (IOException ex) {
            RestResponse error =
                new RestResponse("Invalid JSON content.", RestStatus.BAD_REQUEST.getStatus());
            return new BytesRestResponse(RestStatus.BAD_REQUEST, error.toXContent());
        }

        // Check that there is no ID field
        if (!jsonNode.at("/resource/document/id").isMissingNode()) {
            return new RestResponse("ID field is not allowed in the request body.",
                RestStatus.BAD_REQUEST.getStatus());
        }

        // Generate ID
        String id = UUIDs.base64UUID();

        // Insert ID into /resource/document/id
        JsonNode documentNode = jsonNode.at("/resource/document");
        if (documentNode.isObject()) {
            ((ObjectNode) documentNode).put("id", id);
        }

        WIndexIntegrationResponse sapResponse = service.upsertIntegration(jsonNode);

        if (sapResponse.getStatus() != RestStatus.OK) {
            return new RestResponse(
                "Failed to create Integration, SAP response: " + sapResponse.getStatus(),
                RestStatus.BAD_REQUEST.getStatus());
        }

        // Validate integration
        RestResponse validationResponse = this.engine.validate(jsonNode);

        // If validation failed, delete the created integration in SAP
        if (validationResponse.getStatus() != RestStatus.OK.getStatus()) {
            service.deleteIntegration(id);
            return new RestResponse(
                "Failed to create Integration, Validation response: "
                    + validationResponse.getStatus()
                    + ".", RestStatus.BAD_REQUEST.getStatus());
        }

        // TODO: Add integration to CTI integration draft space
        // TODO: Add integration to draft policy
    }
}
