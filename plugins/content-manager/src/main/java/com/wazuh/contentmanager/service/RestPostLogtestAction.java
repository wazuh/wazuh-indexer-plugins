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
package com.wazuh.contentmanager.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/logtest
 *
 * <p>Triggers a log test execution in the local engine. Possible HTTP responses:
 *
 * <pre>
 *  - 200 Accepted: Wazuh Engine replied with a successful response.
 *  - 400 Bad Request: Wazuh Engine replied with an error response.
 *  - 500 Internal Server Error: Unexpected error during processing. Wazuh Engine did not respond.
 * </pre>
 */
public class RestPostLogtestAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostLogtestAction.class);
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
     * Handles incoming requests.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        RestResponse response = this.handleRequest(request);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    /**
     * Execute the logtest operation.
     *
     * @param request incoming request
     * @return a BytesRestResponse describing the outcome
     */
    public RestResponse handleRequest(RestRequest request) {
        // 1. Check if engine service exists
        if (this.engine == null) {
            log.error(Constants.E_LOG_ENGINE_IS_NULL);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // 2. Check request's payload exists
        if (request == null || !request.hasContent()) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // 3. Check request's payload is valid JSON
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = mapper.readTree(request.content().streamInput());
        } catch (IOException ex) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // 4. Logtest accepted
        try {
            return this.engine.logtest(jsonNode);
        } catch (Exception e) {
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
