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
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.CredentialsIndex;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/subscription
 *
 * <p>Stores the provided CTI access token in the credentials index and in the plugin-wide
 * PluginSettings variable.
 *
 * <p>Possible HTTP responses: - 201 Created: Credentials stored successfully. - 400 Bad Request:
 * Missing or empty access_token field. - 500 Internal Server Error: Unexpected error during
 * processing.
 */
public class RestPostSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_post";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_post";
    private static final String ACCESS_TOKEN_FIELD = "access_token";

    private final CredentialsIndex credentialsIndex;

    /**
     * Constructs the REST handler.
     *
     * @param credentialsIndex the index used to persist the access token
     */
    public RestPostSubscriptionAction(CredentialsIndex credentialsIndex) {
        this.credentialsIndex = credentialsIndex;
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
     * @return route configuration for POST subscription
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.SUBSCRIPTION_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the request for execution.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a RestChannelConsumer to handle the request
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(this.handleRequest(request));
    }

    /**
     * Parses the request payload, validates the access_token field, persists it, and updates the
     * plugin-wide variable.
     *
     * @param request the incoming REST request
     * @return a BytesRestResponse representing the operation result
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest(RestRequest request) throws IOException {
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
            RestResponse error =
                    new RestResponse(
                            "Missing [" + ACCESS_TOKEN_FIELD + "] field.", RestStatus.BAD_REQUEST.getStatus());
            return new BytesRestResponse(RestStatus.BAD_REQUEST, error.toXContent());
        }

        try {
            this.credentialsIndex.storeCredentials(accessToken);
            PluginSettings.getInstance().setAccessToken(accessToken);

            RestResponse response =
                    new RestResponse("Credentials received", RestStatus.CREATED.getStatus());
            return new BytesRestResponse(RestStatus.CREATED, response.toXContent());
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
