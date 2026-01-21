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
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/content-manager/logtest
 *
 * <p>Triggers a log test execution in the local engine.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestPostLogtestAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_logtest";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/engine_logtest";
    private final EngineService engine;

    /**
     * Constructs a new RestPostLogtest.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPostLogtestAction(EngineService engine) {
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
                        .path(PluginSettings.LOGTEST_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepare the request by returning a consumer that executes the update operation.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(this.handleRequest(request));
    }

    /**
     * Execute the logtest operation.
     *
     * @param request incoming request
     * @return a BytesRestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest(RestRequest request) throws IOException {
        try {
            // 1. Check if engine service exists
            if (this.engine == null) {
                RestResponse error =
                        new RestResponse(
                                "Engine instance is null.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent());
            }

            // 2. Check request's payload exists
            if (!request.hasContent()) {
                RestResponse error =
                        new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
                return new BytesRestResponse(RestStatus.BAD_REQUEST, error.toXContent());
            }

            // 3. Check request's payload is valid JSON
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode;
            try {
                jsonNode = mapper.readTree(request.content().streamInput());
            } catch (IOException ex) {
                RestResponse error =
                        new RestResponse("Invalid JSON content.", RestStatus.BAD_REQUEST.getStatus());
                return new BytesRestResponse(RestStatus.BAD_REQUEST, error.toXContent());
            }

            // 4. Logtest accepted
            RestResponse response = this.engine.logtest(jsonNode);
            return new BytesRestResponse(
                    RestStatus.fromCode(response.getStatus()), response.toXContent());
        } catch (Exception e) {
            RestResponse error =
                    new RestResponse(
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : "An unexpected error occurred while processing your request.",
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent());
        }
    }
}
