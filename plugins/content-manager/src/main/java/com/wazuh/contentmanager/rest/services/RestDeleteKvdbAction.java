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
package com.wazuh.contentmanager.rest.services;

import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/content-manager/kvdbs/{id}
 *
 * <p>Deletes an existing KVDB from the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The KVDB exists and is in the draft space.
 *   <li>The KVDB is unlinked from any integrations that reference it.
 *   <li>The KVDB is deleted from the index and the space hash is recalculated.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: KVDB deleted successfully.
 *   <li>400 Bad Request: KVDB is not in draft space.
 *   <li>404 Not Found: KVDB with specified ID was not found.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestDeleteKvdbAction extends AbstractDeleteAction {

    private static final String ENDPOINT_NAME = "content_manager_kvdb_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_delete";

    public RestDeleteKvdbAction(EngineService engine) {
        super(engine);
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the DELETE endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.KVDBS_URI + "/{id}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_KVDBS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_KVDB;
    }

    @Override
    protected void deleteExternalServices(String id) {
        // No explicit KVDB delete in external services
    }

    @Override
    protected void unlinkFromParent(Client client, String id) throws IOException {
        this.contentUtils.unlinkResourceFromIntegrations(client, id, Constants.KEY_KVDBS);
    }
}
