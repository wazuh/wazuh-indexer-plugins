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
import com.wazuh.contentmanager.rest.model.Policy;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * REST handler for updating policy resources on the Wazuh Engine.
 *
 * <p>This endpoint handles PUT requests to update policy configurations in the draft space. The
 * policy defines the root decoder and integrations list for content processing.
 */
public class RestPutPolicyAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_policy_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/policy_update";
    private final EngineService engine;

    /**
     * Constructs a new RestPutPolicyAction handler.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPutPolicyAction(EngineService engine) {
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
                        .path(PluginSettings.POLICY_URI + "/{id}")
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the request by returning a consumer that executes the policy update operation.
     *
     * @param request the incoming REST request containing the policy payload
     * @param client the node client (unused)
     * @return a consumer that executes the policy update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        return channel -> channel.sendResponse(this.handleRequest(request));
    }

    /**
     * Handles the policy update request by validating the payload and storing the policy.
     *
     * <p>This method performs the following validations:
     *
     * <ol>
     *   <li>Checks that the engine service is available
     *   <li>Verifies that the request contains a JSON payload
     *   <li>Parses and validates the Policy JSON structure
     * </ol>
     *
     * @param request incoming REST request containing the policy data
     * @return a BytesRestResponse describing the outcome of the operation
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest(RestRequest request) throws IOException {
        // TODO: Move this logic to a common utility method since it's repeated in multiple handlers.
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
        // 3. Check request's payload is valid Policy JSON
        ObjectMapper mapper = new ObjectMapper();
        Policy policy;
        try {
            policy = mapper.readValue(request.content().streamInput(), Policy.class);
        } catch (IOException e) {
            RestResponse error =
                    new RestResponse(
                            "Invalid Policy JSON content: " + e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
            return new BytesRestResponse(RestStatus.BAD_REQUEST, error.toXContent());
        }
        // 4. Update/create the policy using the engine service. TODO: Implement this logic.
        return new BytesRestResponse(RestStatus.OK, policy.toString());
    }
}
