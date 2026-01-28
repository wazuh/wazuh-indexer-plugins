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

import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.UUIDs;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
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
    private static final Logger log = LogManager.getLogger(RestPutPolicyAction.class);
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
                        .path(PluginSettings.POLICY_URI)
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
        RestResponse response = this.handleRequest(request, client);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
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
     * @param client the node client
     * @return a RestResponse describing the outcome of the operation
     */
    public RestResponse handleRequest(RestRequest request, NodeClient client) {
        // 1. Check if engine service exists
        if (this.engine == null) {
            return new RestResponse(
                    "Engine instance is null.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
        // 2. Check request's payload exists
        if (!request.hasContent()) {
            return new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        // 3. Check request's payload is valid Policy JSON
        ObjectMapper mapper = new ObjectMapper();
        Policy policy;
        try {
            policy = mapper.readValue(request.content().utf8ToString(), Policy.class);
        } catch (IOException e) {
            return new RestResponse(
                    "Invalid Policy JSON content: " + request.content().utf8ToString(),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        // 4. Store the policy in the draft space
        // Search the current draft policy to get the ID
        ContentIndex contentIndex = new ContentIndex(client, ".cti-policies.", null);
        QueryBuilder queryBuilder = QueryBuilders.termQuery("space", "draft");
        JsonObject resource = contentIndex.searchByQuery(queryBuilder);
        log.info("Found existing draft policy: {}", resource);
        // Update the policy using the retrieved ID
        String id =
                (resource != null && resource.has("id"))
                        ? resource.get("id").getAsString()
                        : UUIDs.base64UUID();
        try {
            // If no existing draft policy, will create a new one
            contentIndex.create(id, policy.toJson());
        } catch (IOException e) {
            return new RestResponse(
                    "Failed to store the updated policy: " + e.getMessage(),
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        return new RestResponse(policy.toString(), RestStatus.OK.getStatus());
    }
}
