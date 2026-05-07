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

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.service.PlansService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/_content_manager/subscription
 *
 * <p>Returns the subscription status and active plan. Delegates to {@link PlansService#getPlan()},
 * which routes to the authenticated or public CTI endpoint based on whether an access token is
 * present in {@link PluginSettings}.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Returns plan name, is_public flag, and is_registered state.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestGetSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_get";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_get";
    private final PlansService plansService;

    /**
     * Construct the REST handler.
     *
     * @param plansService the service used to retrieve the active plan
     */
    public RestGetSubscriptionAction(PlansService plansService) {
        this.plansService = plansService;
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.SUBSCRIPTION_URI)
                        .method(GET)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(this.handleRequest());
    }

    /**
     * Builds the subscription status response.
     *
     * @return a {@link BytesRestResponse} with the nested plan and registration state
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            boolean isRegistered = PluginSettings.getInstance().getAccessToken() != null;
            Plan plan = this.plansService.getPlan();

            XContentBuilder builder =
                    XContentFactory.jsonBuilder()
                            .startObject()
                            .startObject("message")
                            .startObject("plan")
                            .field("name", plan != null ? plan.getName() : null)
                            .field("is_public", plan != null && plan.isPublic())
                            .endObject()
                            .field("is_registered", isRegistered)
                            .endObject()
                            .field("status", RestStatus.OK.getStatus())
                            .endObject();

            return new BytesRestResponse(RestStatus.OK, builder);
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
