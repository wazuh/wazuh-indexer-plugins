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
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.service.SubscriptionService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/subscription
 *
 * <p>Stores the provided CTI access token by delegating to {@link
 * SubscriptionService#register(String)}.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: Credentials stored successfully.
 *   <li>400 Bad Request: Missing or empty access_token field.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestPostSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_post";
    private static final String ACCESS_TOKEN_FIELD = "access_token";

    private final SubscriptionService subscriptionService;

    /**
     * Constructs the REST handler.
     *
     * @param subscriptionService the service used to register credentials
     */
    public RestPostSubscriptionAction(SubscriptionService subscriptionService) {
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
     * @return route configuration for the POST endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, PluginSettings.SUBSCRIPTION_URI));
    }

    /**
     * Handles incoming requests by delegating to {@link #handleRequest(RestRequest)}.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the subscription registration response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        RestResponse response = this.handleRequest(request);
        return channel ->
                channel.sendResponse(
                        new BytesRestResponse(
                                RestStatus.fromCode(response.getStatus()), response.toXContent()));
    }

    /**
     * Parses the request payload, validates the access_token field, and delegates to {@link
     * SubscriptionService#register(String)}.
     *
     * @param request the incoming REST request
     * @return a BytesRestResponse representing the operation result
     * @throws IOException if an I/O error occurs while building the response
     */
    public RestResponse handleRequest(RestRequest request) throws IOException {
        String accessToken = null;
        try (XContentParser parser = request.contentParser()) {
            XContentParser.Token token;
            while ((token = parser.nextToken()) != null) {
                if (token == XContentParser.Token.FIELD_NAME
                        && ACCESS_TOKEN_FIELD.equals(parser.currentName())) {
                    parser.nextToken();
                    accessToken = parser.text();
                } else if (token == XContentParser.Token.END_OBJECT) {
                    break;
                }
            }
        }

        if (accessToken == null || accessToken.isBlank()) {
            return new RestResponse(
                    "Missing [" + ACCESS_TOKEN_FIELD + "] field.", RestStatus.BAD_REQUEST.getStatus());
        }

        try {
            this.subscriptionService.register(accessToken);

            return new RestResponse(
                    Constants.S_201_ACCESS_TOKEN_RECEIVED, RestStatus.CREATED.getStatus());
        } catch (IllegalStateException e) {
            if (e.getMessage().equals(Constants.E_412_UNPROTECTED_CREDENTIALS_INDEX)) {
                return new RestResponse(e.getMessage(), RestStatus.PRECONDITION_FAILED.getStatus());
            }
            throw e;
        } catch (Exception e) {
            return new RestResponse(
                    e.getMessage() != null
                            ? e.getMessage()
                            : "An unexpected error occurred while processing your request.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
