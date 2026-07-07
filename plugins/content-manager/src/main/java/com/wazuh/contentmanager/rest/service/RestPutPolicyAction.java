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

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.UpdatePolicyAction;
import com.wazuh.contentmanager.action.UpdatePolicyRequest;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * PUT /_plugins/_content_manager/policy/{space}
 *
 * <p>Updates a policy resource. Delegates to the transport action {@link
 * com.wazuh.contentmanager.transport.TransportUpdatePolicyAction}.
 */
public class RestPutPolicyAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutPolicyAction.class);
    private static final String ENDPOINT_NAME = "content_manager_policy_update";

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(PUT, PluginSettings.POLICY_URI + "/{space}"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug("{} {}", request.method(), PluginSettings.POLICY_URI);

        String space = request.param(Constants.KEY_SPACE);
        String body = request.hasContent() ? request.content().utf8ToString() : null;
        UpdatePolicyRequest policyRequest = new UpdatePolicyRequest(space, body);
        return channel ->
                client.execute(UpdatePolicyAction.INSTANCE, policyRequest, createResponseListener(channel));
    }

    private RestResponseListener<MessageStatusResponse> createResponseListener(RestChannel channel) {
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
