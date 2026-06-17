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
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.action.GetSubscriptionAction;
import com.wazuh.contentmanager.action.GetSubscriptionRequest;
import com.wazuh.contentmanager.action.GetSubscriptionResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/_content_manager/subscription
 *
 * <p>Returns the subscription status and active plan. Delegates to the transport action {@link
 * GetSubscriptionAction}, which calls {@link
 * com.wazuh.contentmanager.cti.catalog.service.SubscriptionService#getPlan()}.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Returns plan name, is_public flag, and is_registered state.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestGetSubscriptionAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestGetSubscriptionAction.class);
    private static final String ENDPOINT_NAME = "content_manager_subscription_get";

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the GET endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, PluginSettings.SUBSCRIPTION_URI));
    }

    /**
     * Delegates to the transport action via {@link GetSubscriptionAction}.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the subscription status response
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug(
                String.format(
                        Locale.getDefault(), "%s %s", request.method(), PluginSettings.SUBSCRIPTION_URI));

        GetSubscriptionRequest subscriptionRequest = new GetSubscriptionRequest();
        return channel ->
                client.execute(
                        GetSubscriptionAction.INSTANCE,
                        subscriptionRequest,
                        createResponseListener(channel));
    }

    private RestResponseListener<GetSubscriptionResponse> createResponseListener(
            RestChannel channel) {
        return new RestResponseListener<>(channel) {
            @Override
            public org.opensearch.rest.RestResponse buildResponse(GetSubscriptionResponse response)
                    throws Exception {
                return new BytesRestResponse(
                        response.getStatus(),
                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }
}
