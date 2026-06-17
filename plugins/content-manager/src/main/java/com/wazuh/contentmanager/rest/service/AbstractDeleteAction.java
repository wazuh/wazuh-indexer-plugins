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
import org.opensearch.action.ActionType;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;

import com.wazuh.contentmanager.action.ContentDeleteRequest;
import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Abstract handler for deleting content resources (non-Spaces variant).
 *
 * <p>Delegates to the transport layer via {@code client.execute()}.
 */
public abstract class AbstractDeleteAction extends AbstractContentAction {

    private static final Logger log = LogManager.getLogger(AbstractDeleteAction.class);

    public AbstractDeleteAction() {
        super();
    }

    protected abstract ActionType<ContentResponse> getActionType();

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        String id = request.param(Constants.KEY_ID);

        log.debug("{} {}", request.method(), request.path());

        ContentDeleteRequest deleteRequest = new ContentDeleteRequest(request.method(), id);

        return channel ->
                client.execute(
                        getActionType(),
                        deleteRequest,
                        new RestResponseListener<ContentResponse>(channel) {
                            @Override
                            public org.opensearch.rest.RestResponse buildResponse(
                                    ContentResponse response) throws Exception {
                                return new BytesRestResponse(
                                        org.opensearch.core.rest.RestStatus.fromCode(
                                                response.getStatus()),
                                        response.toXContent(
                                                XContentFactory.jsonBuilder(),
                                                ToXContent.EMPTY_PARAMS));
                            }
                        });
    }
}
