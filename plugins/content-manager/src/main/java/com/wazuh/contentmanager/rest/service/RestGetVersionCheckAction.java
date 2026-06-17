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

import com.wazuh.contentmanager.action.VersionCheckAction;
import com.wazuh.contentmanager.action.VersionCheckRequest;
import com.wazuh.contentmanager.action.VersionCheckResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/_content_manager/version/check
 *
 * <p>Returns available Wazuh version updates. Delegates to the transport action {@link
 * com.wazuh.contentmanager.transport.TransportVersionCheckAction}.
 */
public class RestGetVersionCheckAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestGetVersionCheckAction.class);
    private static final String ENDPOINT_NAME = "content_manager_version_check_get";

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, PluginSettings.VERSION_CHECK_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug("{} {}", request.method(), PluginSettings.VERSION_CHECK_URI);

        VersionCheckRequest versionCheckRequest = new VersionCheckRequest();
        return channel ->
                client.execute(
                        VersionCheckAction.INSTANCE,
                        versionCheckRequest,
                        createResponseListener(channel));
    }

    private RestResponseListener<VersionCheckResponse> createResponseListener(RestChannel channel) {
        return new RestResponseListener<>(channel) {
            @Override
            public org.opensearch.rest.RestResponse buildResponse(VersionCheckResponse response)
                    throws Exception {
                return new BytesRestResponse(
                        response.getStatus(),
                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }
}
