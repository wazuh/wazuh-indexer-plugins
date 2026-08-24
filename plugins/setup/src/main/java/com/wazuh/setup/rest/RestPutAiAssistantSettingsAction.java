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
 * {@code PUT /_plugins/_setup/ai_assistant/settings} — upserts the AI assistant's settings/field
 * policy document in the shared {@code .wazuh-internal-state} system index. Restricted to callers
 * holding the {@code plugin:wazuh/ai_assistant/settings/write} cluster permission.
 */
public class RestPutAiAssistantSettingsAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "ai_assistant_put_settings";
    private static final String SETTINGS_URI = "/_plugins/_setup/ai_assistant/settings";

    /** Default constructor. */
    public RestPutAiAssistantSettingsAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.PUT, SETTINGS_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String payload = request.hasContent() ? request.content().utf8ToString() : null;
        PutAiAssistantSettingsRequest putRequest =
                new PutAiAssistantSettingsRequest(Operation.SETTINGS, null, payload);
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
