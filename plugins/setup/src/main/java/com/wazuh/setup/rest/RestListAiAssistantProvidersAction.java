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
package com.wazuh.setup.rest;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.setup.action.GetAiAssistantSettingsAction;
import com.wazuh.setup.action.GetAiAssistantSettingsRequest;
import com.wazuh.setup.action.GetAiAssistantSettingsRequest.Operation;
import com.wazuh.setup.action.GetAiAssistantSettingsResponse;

/**
 * {@code GET /_plugins/_setup/ai_assistant/providers} — lists every AI assistant provider document
 * in the shared {@code .wazuh-internal-state} system index. Restricted to callers holding the
 * {@code plugin:wazuh/ai_assistant/settings/read} cluster permission.
 */
public class RestListAiAssistantProvidersAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "ai_assistant_list_providers";
    private static final String PROVIDERS_URI = "/_plugins/_setup/ai_assistant/providers";

    /** Default constructor. */
    public RestListAiAssistantProvidersAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.GET, PROVIDERS_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        GetAiAssistantSettingsRequest getRequest =
                new GetAiAssistantSettingsRequest(Operation.LIST_PROVIDERS);
        return channel ->
                client.execute(
                        GetAiAssistantSettingsAction.INSTANCE,
                        getRequest,
                        new RestResponseListener<GetAiAssistantSettingsResponse>(channel) {
                            @Override
                            public org.opensearch.rest.RestResponse buildResponse(
                                    GetAiAssistantSettingsResponse response) throws Exception {
                                return new BytesRestResponse(
                                        RestStatus.OK,
                                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
                            }
                        });
    }
}
