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

import com.wazuh.setup.action.SearchSessionsAction;
import com.wazuh.setup.action.SearchSessionsRequest;
import com.wazuh.setup.action.SearchSessionsResponse;
import com.wazuh.setup.index.AiAssistantSessionsAdminIndex;

/**
 * GET /_plugins/_setup/ai_assistant/sessions
 *
 * <p>Searches AI assistant conversations across every user, or one user when the {@code user} query
 * parameter is given. Bypasses the per-owner Document Level Security that ordinary index access to
 * {@code wazuh-ai-assistant-sessions} is subject to; restricted to callers holding the {@code
 * plugin:wazuh/ai_assistant/sessions/read} cluster permission.
 */
public class RestSearchSessionsAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "ai_assistant_search_sessions";
    private static final String URI = "/_plugins/_setup/ai_assistant/sessions";
    private static final String USER_PARAM = "user";
    private static final String SIZE_PARAM = "size";
    private static final int DEFAULT_SIZE = 100;

    /** Default constructor. */
    public RestSearchSessionsAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.GET, URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String user = request.param(USER_PARAM);
        int size = request.paramAsInt(SIZE_PARAM, DEFAULT_SIZE);
        if (size <= 0 || size > AiAssistantSessionsAdminIndex.MAX_SEARCH_SIZE) {
            return channel ->
                    channel.sendResponse(
                            new BytesRestResponse(
                                    RestStatus.BAD_REQUEST,
                                    String.format(
                                            java.util.Locale.ROOT,
                                            "'%s' must be between 1 and %d.",
                                            SIZE_PARAM,
                                            AiAssistantSessionsAdminIndex.MAX_SEARCH_SIZE)));
        }

        SearchSessionsRequest searchRequest = new SearchSessionsRequest(user, size);
        return channel ->
                client.execute(
                        SearchSessionsAction.INSTANCE,
                        searchRequest,
                        new RestResponseListener<SearchSessionsResponse>(channel) {
                            @Override
                            public org.opensearch.rest.RestResponse buildResponse(SearchSessionsResponse response)
                                    throws Exception {
                                return new BytesRestResponse(
                                        RestStatus.OK,
                                        response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
                            }
                        });
    }
}
