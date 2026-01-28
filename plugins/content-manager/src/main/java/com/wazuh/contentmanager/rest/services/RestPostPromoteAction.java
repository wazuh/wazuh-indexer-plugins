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

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.model.SpaceDiff;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/promote
 *
 * <p>Execute promotion process in the local engine. Possible HTTP responses:
 *
 * <pre>
 *  - 200 Accepted: Wazuh Engine replied with a successful response.
 *  - 400 Bad Request: Wazuh Engine replied with an error response.
 *  - 500 Internal Server Error: Unexpected error during processing. Wazuh Engine did not respond.
 * </pre>
 */
public class RestPostPromoteAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_promote";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/promote";
    private final EngineService engine;

    /**
     * Constructor.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPostPromoteAction(EngineService engine) {
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
                        .path(PluginSettings.PROMOTE_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Handles incoming requests.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        RestResponse response = this.handleRequest(request);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    /**
     * Execute the space promotion operation.
     *
     * @param request incoming request
     * @return a RestResponse
     */
    public RestResponse handleRequest(RestRequest request) {
        try {
            // 0. Common validations
            if (this.engine == null) {
                return new RestResponse(
                        "Engine instance is null.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }
            if (request == null || !request.hasContent()) {
                return new RestResponse(
                        "JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
            }

            // 1. Payload validation
            ObjectMapper mapper = new ObjectMapper();
            SpaceDiff spaceDiff;
            try {
                spaceDiff = mapper.readValue(request.content().utf8ToString(), SpaceDiff.class);
            } catch (IOException e) {
                return new RestResponse(
                        "Invalid JSON: " + e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
            }

            // 2. Policy gathering
            // TODO
            JsonNode engine_payload = null;

            // 3. Promote
            RestResponse response = this.engine.promote(engine_payload);
            if (response.getStatus() != RestStatus.OK.getStatus()) {
                return response;
            }
            // TODO Update the resources' space

            // TODO Regenerate the space hash

            // Reply with a 200 OK (already 200 is we reached this point)
            response.setMessage("Promotion complete.");
            return response;
        } catch (Exception e) {
            return new RestResponse(
                    e.getMessage() != null
                            ? e.getMessage()
                            : "An unexpected error occurred while processing your request.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
