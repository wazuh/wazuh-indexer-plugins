/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.service.SubscriptionService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/_content_manager/subscription
 *
 * <p>Removes stored CTI credentials by delegating to {@link SubscriptionService#unregister()},
 * which clears both the credentials document in {@code .wazuh-cti-credentials} and the in-memory
 * token in {@link PluginSettings}.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Credentials removed successfully.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestDeleteSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_delete";
    private final SubscriptionService subscriptionService;

    /**
     * Create a new REST action.
     *
     * @param subscriptionService the service used to remove stored credentials
     */
    public RestDeleteSubscriptionAction(SubscriptionService subscriptionService) {
        this.subscriptionService = subscriptionService;
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the DELETE endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.SUBSCRIPTION_URI)
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Handles incoming requests by delegating to {@link #handleRequest()}.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the credential removal response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(this.handleRequest());
    }

    /**
     * Delegates to {@link SubscriptionService#unregister()} and returns the appropriate response.
     *
     * @return a {@link BytesRestResponse} representing the operation result
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            this.subscriptionService.unregister();
            RestResponse response = new RestResponse("Credentials removed", RestStatus.OK.getStatus());
            return new BytesRestResponse(RestStatus.OK, response.toXContent());
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
