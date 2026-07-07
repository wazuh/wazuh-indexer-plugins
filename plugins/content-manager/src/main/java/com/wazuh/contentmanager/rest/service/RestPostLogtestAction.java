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
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.contentmanager.action.LogtestAction;
import com.wazuh.contentmanager.action.LogtestRequest;
import com.wazuh.contentmanager.action.LogtestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/logtest
 *
 * <p>Thin REST layer that delegates to {@link
 * com.wazuh.contentmanager.transport.TransportLogtestAction} via the transport layer.
 */
public class RestPostLogtestAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostLogtestAction.class);
    private static final String ENDPOINT_NAME = "content_manager_logtest";

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the logtest endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, PluginSettings.LOGTEST_URI));
    }

    /**
     * Parses the request body and delegates to the transport action.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the logtest response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug("{} {}", request.method(), PluginSettings.LOGTEST_URI);

        String body = request.content().utf8ToString();
        LogtestRequest logtestRequest = new LogtestRequest(body);

        return channel ->
                client.execute(LogtestAction.INSTANCE, logtestRequest, createResponseListener(channel));
    }

    private RestResponseListener<LogtestResponse> createResponseListener(RestChannel channel) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(LogtestResponse response) throws Exception {
                return new BytesRestResponse(
                        response.getStatus(),
                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }
}
