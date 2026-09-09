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
 * {@code PUT /_plugins/_setup/ai_assistant/sessions/{id}} — replaces the session's {@code
 * messages}, and its {@code title} when one is sent.
 *
 * <p>{@code title} is optional: absent means keep the stored one, so an auto-save that resends only
 * the transcript cannot revert a rename. {@code expected_version} widens the optimistic-concurrency
 * check from "since this request started" to "since the caller last read". A session owned by
 * somebody else is reported as {@code 404}, never {@code 403}. Restricted to callers holding the
 * {@code plugin:wazuh/ai_assistant/session/write} cluster permission.
 */
public class RestPutAiAssistantSessionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "ai_assistant_put_session";
    private static final String SESSION_BY_ID_URI = "/_plugins/_setup/ai_assistant/sessions/{id}";
    private static final String ID_PARAM = "id";

    /** Default constructor. */
    public RestPutAiAssistantSessionAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.PUT, SESSION_BY_ID_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        // The body is forwarded raw and parsed in the transport action, never here.
        String payload = request.hasContent() ? request.content().utf8ToString() : null;
        PutAiAssistantSessionRequest sessionRequest =
                new PutAiAssistantSessionRequest(Operation.UPDATE, request.param(ID_PARAM), payload);
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
