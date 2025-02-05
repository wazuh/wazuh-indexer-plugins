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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.action.cti.GetCatalogAction;

import static org.opensearch.rest.RestRequest.Method.GET;

public class CatalogHandler extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(CatalogHandler.class);

    public static final String GET_CATALOG_DETAILS = "get_catalog_details";

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(
                        GET,
                        String.format(Locale.ROOT, "%s", "/_plugins/_content_manager/vd-catalog")));
    }

    @Override
    public String getName() {
        return GET_CATALOG_DETAILS;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        switch (request.method()) {
            case GET:
                return restChannel -> {
                    restChannel.sendResponse(GetCatalogAction.run());
                };
            default:
                throw new IllegalArgumentException(
                        ("Unsupported HTTP method " + request.method().name()));
        }
    }
}
