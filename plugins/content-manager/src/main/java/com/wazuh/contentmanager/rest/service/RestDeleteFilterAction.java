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

import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.util.List;

import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST handler for deleting Engine Filters.
 *
 * <p>Endpoint: DELETE /_plugins/content-manager/filters/{filter_id}
 *
 * <p>This handler processes filter deletion requests.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Filter deleted successfully.
 *   <li>400 Bad Request: Filter ID is missing or invalid.
 *   <li>404 Not found: Filter index or Filter ID was not found.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestDeleteFilterAction extends AbstractDeleteActionSpaces {

    private static final String ENDPOINT_NAME = "content_manager_filter_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/filter_delete";

    public RestDeleteFilterAction(EngineService engine) {
        super(engine);
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the delete endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.FILTERS_URI + "/{id}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_FILTERS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_FILTER;
    }

    @Override
    protected void deleteExternalServices(String id) {
        // Not applicable for this implementation.
    }

    @Override
    protected void unlinkFromParent(Client client, String id) throws Exception {
        // Not applicable for this implementation.
    }
}
