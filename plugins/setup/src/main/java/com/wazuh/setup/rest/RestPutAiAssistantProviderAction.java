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
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.setup.action.PutAiAssistantSettingsAction;
import com.wazuh.setup.action.PutAiAssistantSettingsRequest;
import com.wazuh.setup.action.PutAiAssistantSettingsRequest.Operation;
import com.wazuh.setup.action.PutAiAssistantSettingsResponse;

/**
 * {@code PUT /_plugins/_setup/ai_assistant/providers/{id}} — creates or updates the AI assistant
 * provider document with the given id in the shared {@code .wazuh-internal-state} system index.
 * Restricted to callers holding the {@code plugin:wazuh/ai_assistant/settings/write} cluster
 * permission.
 */
public class RestPutAiAssistantProviderAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "ai_assistant_put_provider";
    private static final String PROVIDER_BY_ID_URI = "/_plugins/_setup/ai_assistant/providers/{id}";
    private static final String ID_PARAM = "id";

    /** Default constructor. */
    public RestPutAiAssistantProviderAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.PUT, PROVIDER_BY_ID_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String payload = request.hasContent() ? request.content().utf8ToString() : null;
        PutAiAssistantSettingsRequest putRequest =
                new PutAiAssistantSettingsRequest(Operation.PUT_PROVIDER, request.param(ID_PARAM), payload);
        return channel ->
                client.execute(
                        PutAiAssistantSettingsAction.INSTANCE,
                        putRequest,
                        new RestResponseListener<PutAiAssistantSettingsResponse>(channel) {
                            @Override
                            public org.opensearch.rest.RestResponse buildResponse(
                                    PutAiAssistantSettingsResponse response) throws Exception {
                                return new BytesRestResponse(
                                        response.getStatus(),
                                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
                            }
                        });
    }
}
