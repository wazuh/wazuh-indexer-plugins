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
package com.wazuh.contentmanager.rest;

import org.apache.hc.core5.http.message.BasicHeader;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.PluginSettings;
import com.wazuh.contentmanager.http.GetClient;

import static org.opensearch.rest.RestRequest.Method.GET;

public class GetHandler extends BaseRestHandler {

    public static final String GET_CONTENT_MANAGER_INIT_DETAILS =
            "get_content_manager_init_details";

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(GET, String.format(Locale.ROOT, "%s", "_plugins/_content_manager/init")));
    }

    @Override
    public String getName() {
        return GET_CONTENT_MANAGER_INIT_DETAILS;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        switch (request.method()) {
            case GET:
                GetClient.getInstance()
                        .get(
                                URI.create(PluginSettings.getInstance().getUri()),
                                null,
                                new BasicHeader("authorization", "Bearer: API-TOKEN"));

                return null;
            default:
                throw new IllegalArgumentException(
                        ("Unsupported HTTP method " + request.method().name()));
        }
    }
}
