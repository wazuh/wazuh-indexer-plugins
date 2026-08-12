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

import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.setup.action.DeleteSessionAction;
import com.wazuh.setup.action.DeleteSessionRequest;
import com.wazuh.setup.action.DeleteSessionResponse;

/**
 * DELETE /_plugins/_setup/ai_assistant/sessions/{id}
 *
 * <p>Deletes a single AI assistant conversation regardless of which user owns it. Bypasses the
 * per-owner Document Level Security that ordinary index access to {@code
 * wazuh-ai-assistant-sessions} is subject to; restricted to callers holding the {@code
 * plugin:wazuh/ai_assistant/sessions/write} cluster permission.
 */
public class RestDeleteSessionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "ai_assistant_delete_session";
    private static final String URI = "/_plugins/_setup/ai_assistant/sessions/{id}";
    private static final String ID_PARAM = "id";

    /** Default constructor. */
    public RestDeleteSessionAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.DELETE, URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        DeleteSessionRequest deleteRequest = new DeleteSessionRequest(request.param(ID_PARAM));
        return channel ->
                client.execute(
                        DeleteSessionAction.INSTANCE,
                        deleteRequest,
                        new RestResponseListener<DeleteSessionResponse>(channel) {
                            @Override
                            public org.opensearch.rest.RestResponse buildResponse(
                                    DeleteSessionResponse response) {
                                return new RestResponse(response.getMessage(), response.getStatus().getStatus())
                                        .toBytesRestResponse();
                            }
                        });
    }
}
