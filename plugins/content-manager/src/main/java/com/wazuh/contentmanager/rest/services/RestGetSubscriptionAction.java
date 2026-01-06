/*
 * Copyright (C) 2024, Wazuh Inc.
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

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/content-manager/subscription
 *
 * <p>Retrieves the current CTI subscription token.
 *
 * <p>Possible HTTP responses: - 200 OK: Subscription found, returns access token and token type -
 * 404 Not Found: The token does not exist - 401 Unauthorized: The endpoint is being accessed by a
 * different user, the expected user is wazuh-server - 500 Internal Server Error: Unexpected error
 * during processing
 */
public class RestGetSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_get";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_get";
    private final CtiConsole ctiConsole;

    /**
     * Construct the REST handler.
     *
     * @param console the CTI console used to retrieve the token
     */
    public RestGetSubscriptionAction(CtiConsole console) {
        this.ctiConsole = console;
    }

    /**
     * Return a short name identifying this handler.
     *
     * @return a short name identifying this handler
     */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return the route configuration for this handler
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.SUBSCRIPTION_URI)
                        .method(GET)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepare the request by returning a consumer that executes the lookup and sends the appropriate
     * response. Query parameters and request body are ignored for this endpoint.
     *
     * @param request the incoming REST request
     * @param client the node client (unused)
     * @return a RestChannelConsumer that produces the response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            channel.sendResponse(this.handleRequest());
        };
    }

    /**
     * Execute the get-subscription operation.
     *
     * @return a BytesRestResponse containing the token information or error
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            Token token = this.ctiConsole.getToken();
            if (token == null) {
                RestResponse error = new RestResponse("Token not found", RestStatus.NOT_FOUND.getStatus());
                return new BytesRestResponse(RestStatus.NOT_FOUND, error.toXContent());
            }
            return new BytesRestResponse(RestStatus.OK, token.toXContent());
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
