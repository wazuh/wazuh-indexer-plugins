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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.action.IndexSubscriptionAction;
import com.wazuh.contentmanager.action.IndexSubscriptionRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/subscription
 *
 * <p>Parses the {@code access_token} field from the JSON body and delegates to the transport
 * action, which calls {@link
 * com.wazuh.contentmanager.cti.catalog.service.SubscriptionService#register(String)}.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: Credentials stored successfully.
 *   <li>400 Bad Request: Missing or empty access_token field.
 *   <li>412 Precondition Failed: Credentials index is not a system index.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestPostSubscriptionAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostSubscriptionAction.class);
    private static final String ENDPOINT_NAME = "content_manager_subscription_post";
    private static final String ACCESS_TOKEN_FIELD = "access_token";

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
     * Parses the {@code access_token} field from the request body and delegates to the transport
     * action via {@link IndexSubscriptionAction}.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the subscription registration response
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {

        log.debug("{} {}", request.method(), PluginSettings.SUBSCRIPTION_URI);

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

        IndexSubscriptionRequest subscriptionRequest = new IndexSubscriptionRequest(accessToken);
        return channel ->
                client.execute(
                        IndexSubscriptionAction.INSTANCE,
                        subscriptionRequest,
                        createSubscriptionResponse(channel));
    }

    private RestResponseListener<MessageStatusResponse> createSubscriptionResponse(
            RestChannel channel) {
        return new RestResponseListener<>(channel) {
            @Override
            public org.opensearch.rest.RestResponse buildResponse(MessageStatusResponse response)
                    throws Exception {
                return new BytesRestResponse(
                        response.getStatus(),
                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }
}
