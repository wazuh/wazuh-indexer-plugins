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
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.TriggerUpdateAction;
import com.wazuh.contentmanager.action.TriggerUpdateRequest;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/update
 *
 * <p>Triggers a CTI content update operation by delegating to the transport action, which calls
 * {@link com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob#trigger()}.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>202 Accepted: Update request accepted for processing.
 *   <li>409 Conflict: A content update is already in progress.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestPostUpdateAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostUpdateAction.class);
    private static final String ENDPOINT_NAME = "content_manager_subscription_update";

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
        return List.of(new Route(POST, PluginSettings.UPDATE_URI));
    }

    /**
     * Delegates to the transport action via {@link TriggerUpdateAction}.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the update trigger response
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug("{} {}", request.method(), PluginSettings.UPDATE_URI);

        TriggerUpdateRequest triggerRequest = new TriggerUpdateRequest();
        return channel ->
                client.execute(
                        TriggerUpdateAction.INSTANCE, triggerRequest, createMessageStatusResponse(channel));
    }

    private RestResponseListener<MessageStatusResponse> createMessageStatusResponse(
            RestChannel channel) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(MessageStatusResponse response) throws Exception {
                return new BytesRestResponse(
                        response.getStatus(),
                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }
}
