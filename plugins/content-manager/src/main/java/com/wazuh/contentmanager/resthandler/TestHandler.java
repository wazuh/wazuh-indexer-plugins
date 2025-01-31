/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.resthandler;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.*;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.action.cti.ContextConsumersEnum;
import com.wazuh.contentmanager.action.cti.GetConsumersAction;
import com.wazuh.contentmanager.model.ctiapi.ContextConsumerCatalog;
import com.wazuh.contentmanager.privileged.PrivilegedActionRunner;

import static org.opensearch.rest.RestRequest.Method.GET;

public class TestHandler extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(TestHandler.class);

    public static final String GET_CONTENT_MANAGER_INIT_DETAILS =
            "get_content_manager_init_details";

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(
                        GET, String.format(Locale.ROOT, "%s", "/_plugins/_content_manager/init")));
    }

    @Override
    public String getName() {
        return GET_CONTENT_MANAGER_INIT_DETAILS;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        List<SimpleHttpResponse> responses = new ArrayList<>();
        XContent xContent = XContentType.JSON.xContent();
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startArray();
        switch (request.method()) {
            case GET:
                for (ContextConsumersEnum context : ContextConsumersEnum.values()) {
                    responses.add(
                            PrivilegedActionRunner.run(
                                    new GetConsumersAction(context.getContextConsumerEndpoint())));
                    ContextConsumerCatalog.parse(
                                    xContent.createParser(
                                            NamedXContentRegistry.EMPTY,
                                            DeprecationHandler.IGNORE_DEPRECATIONS,
                                            responses.get(responses.size() - 1).getBodyBytes()))
                            .toXContent(builder, ToXContent.EMPTY_PARAMS);
                }
                builder.endArray();
                return restChannel -> {
                    restChannel.sendResponse(
                            new BytesRestResponse(
                                    RestStatus.fromCode(
                                            responses.get(responses.size() - 1).getCode()),
                                    builder.toString()));
                };
            default:
                throw new IllegalArgumentException(
                        ("Unsupported HTTP method " + request.method().name()));
        }
    }
}
