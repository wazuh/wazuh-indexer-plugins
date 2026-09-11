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

import com.wazuh.setup.action.PutAiAssistantSessionAction;
import com.wazuh.setup.action.PutAiAssistantSessionRequest;
import com.wazuh.setup.action.PutAiAssistantSessionRequest.Operation;
import com.wazuh.setup.action.PutAiAssistantSessionResponse;

/**
 * {@code POST /_plugins/_setup/ai_assistant/sessions} — creates a session in the {@code
 * wazuh-ai-assistant-sessions} data stream, owned by the authenticated caller.
 *
 * <p>Only {@code title} and {@code messages} are read from the body. {@code user}, {@code
 * @timestamp}, {@code created_at} and {@code updated_at} are stamped by the server and a value sent
 * for any of them is discarded, not rejected. Returns {@code 200}, not {@code 201}, matching {@code
 * POST /ai_assistant/providers}. Restricted to callers holding the {@code
 * plugin:wazuh/ai_assistant/session/write} cluster permission.
 */
public class RestPostAiAssistantSessionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "ai_assistant_post_session";
    private static final String SESSIONS_URI = "/_plugins/_setup/ai_assistant/sessions";

    /** Default constructor. */
    public RestPostAiAssistantSessionAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.POST, SESSIONS_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        // The body is forwarded raw and parsed in the transport action, never here.
        String payload = request.hasContent() ? request.content().utf8ToString() : null;
        PutAiAssistantSessionRequest sessionRequest =
                new PutAiAssistantSessionRequest(Operation.CREATE, null, payload);
        return channel ->
                client.execute(
                        PutAiAssistantSessionAction.INSTANCE,
                        sessionRequest,
                        new RestResponseListener<PutAiAssistantSessionResponse>(channel) {
                            @Override
                            public org.opensearch.rest.RestResponse buildResponse(
                                    PutAiAssistantSessionResponse response) throws Exception {
                                return new BytesRestResponse(
                                        response.getStatus(),
                                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
                            }
                        });
    }
}
