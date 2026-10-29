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

import com.wazuh.contentmanager.action.DeleteSpaceAction;
import com.wazuh.contentmanager.action.DeleteSpaceRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.rest.model.SpaceClearScope;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/_content_manager/space/{space}/normalization
 *
 * <p>Clears only the normalization resources (decoders, kvdbs, filters and the policy root decoder)
 * of the draft space, leaving the detection side untouched. Delegates to {@link DeleteSpaceAction}
 * with the {@link SpaceClearScope#NORMALIZATION} scope, so it reuses the reset endpoint's
 * permission and draft-only restriction.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Normalization resources cleared successfully.
 *   <li>400 Bad Request: Missing space parameter, invalid space string, or a space other than
 *       draft.
 *   <li>500 Internal Server Error: Engine unavailable or unexpected error.
 * </ul>
 */
public class RestDeleteSpaceNormalizationAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestDeleteSpaceNormalizationAction.class);
    private static final String ENDPOINT_NAME = "content_manager_space_clear_normalization";

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(DELETE, PluginSettings.SPACE_URI + "/{space}/normalization"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String spaceName = request.param(Constants.KEY_SPACE);
        log.debug("{} {}/{}/normalization", request.method(), PluginSettings.SPACE_URI, spaceName);
        DeleteSpaceRequest deleteSpaceRequest =
                new DeleteSpaceRequest(spaceName, SpaceClearScope.NORMALIZATION);

        return channel ->
                client.execute(
                        DeleteSpaceAction.INSTANCE, deleteSpaceRequest, createResponseListener(channel));
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
