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

import com.wazuh.contentmanager.action.GetPromoteAction;
import com.wazuh.contentmanager.action.GetPromoteRequest;
import com.wazuh.contentmanager.action.GetPromoteResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/content-manager/promote
 *
 * <p>Previews the promotion of content from one space to another. Delegates to the transport action
 * {@link com.wazuh.contentmanager.transport.TransportGetPromoteAction}.
 */
public class RestGetPromoteAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_promote_preview";
    private static final Logger log = LogManager.getLogger(RestGetPromoteAction.class);

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, PluginSettings.PROMOTE_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug("{} {}", request.method(), PluginSettings.PROMOTE_URI);

        String space = request.param(Constants.KEY_SPACE);
        GetPromoteRequest promoteRequest = new GetPromoteRequest(space);
        return channel ->
                client.execute(
                        GetPromoteAction.INSTANCE,
                        promoteRequest,
                        createResponseListener(channel));
    }

    private RestResponseListener<GetPromoteResponse> createResponseListener(RestChannel channel) {
        return new RestResponseListener<>(channel) {
            @Override
            public org.opensearch.rest.RestResponse buildResponse(GetPromoteResponse response)
                    throws Exception {
                return new BytesRestResponse(
                        response.getStatus(),
                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }
}
