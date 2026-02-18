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
package com.wazuh.contentmanager.service;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/content-manager/subscription
 *
 * <p>Deletes the current CTI subscription.
 *
 * <p>Possible HTTP responses: - 200 OK: Subscription successfully deleted - 404 Not Found: No
 * subscription exists to delete - 401 Unauthorized: The endpoint is being accessed by a different
 * user, the expected user is wazuh-dashboard - 500 Internal Server Error: Unexpected error during
 * processing
 */
public class RestDeleteSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_delete";
    private final CtiConsole ctiConsole;

    /**
     * Create a new REST action.
     *
     * @param ctiConsole the CTI console used to access and delete subscription tokens
     */
    public RestDeleteSubscriptionAction(CtiConsole ctiConsole) {
        this.ctiConsole = ctiConsole;
    }

    /**
     * Return a short identifier for this handler.
     *
     * @return a short identifier for this handler
     */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Define the routes handled by this action.
     *
     * @return the list of routes exposed by this handler (DELETE subscription)
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
     * Prepare the request by returning a channel consumer that executes the deletion and sends the
     * corresponding response. This endpoint ignores request body and query parameters.
     *
     * @param request the incoming REST request
     * @param client the node client (unused)
     * @return a consumer that will be executed to produce a response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(this.handleRequest());
    }

    /**
     * Execute the delete-subscription operation.
     *
     * @return a {@link BytesRestResponse} representing the HTTP response
     * @throws IOException propagated if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            Token token = this.ctiConsole.getToken();
            if (token == null) {
                RestResponse error = new RestResponse("Token not found", RestStatus.NOT_FOUND.getStatus());
                return new BytesRestResponse(RestStatus.NOT_FOUND, error.toXContent());
            }

            this.ctiConsole.deleteToken();

            RestResponse response =
                    new RestResponse("Subscription deleted successfully", RestStatus.OK.getStatus());
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
