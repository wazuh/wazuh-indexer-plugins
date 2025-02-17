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

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;

import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.action.cti.GetCatalogAction;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * Handler class for the catalog endpoint. This is meant for testing purposes until we have a
 * functional JobScheduler job to trigger the CTI API-related logic
 */
public class CatalogHandler extends BaseRestHandler {

    public static final String GET_CATALOG_DETAILS = "get_catalog_details";

    /** Exposes a route */
    @Override
    public List<Route> routes() {
        return List.of(
                new Route(GET, String.format(Locale.ROOT, "%s", "/_plugins/_content_manager/vd-catalog")));
    }

    @Override
    public String getName() {
        return GET_CATALOG_DETAILS;
    }

    /** Handles the actual request to the plugin's catalog endpoint */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        switch (request.method()) {
            case GET:
                return restChannel -> {
                    restChannel.sendResponse(GetCatalogAction.run());
                };
            default:
                throw new IllegalArgumentException(("Unsupported HTTP method " + request.method().name()));
        }
    }
}
