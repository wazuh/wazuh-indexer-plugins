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
package com.wazuh.contentmanager.service;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/content-manager/kvdbs
 *
 * <p>Creates a new KVDB in the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The payload contains all mandatory fields (title, author, content).
 *   <li>The parent integration exists and is in the draft space.
 *   <li>A new UUID and creation timestamps are generated.
 *   <li>The KVDB content is validated by the Engine.
 *   <li>The KVDB is indexed in the draft space.
 *   <li>The new KVDB is linked to the parent Integration.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: KVDB created successfully.
 *   <li>400 Bad Request: Missing fields, invalid payload, or Engine validation failure.
 *   <li>500 Internal Server Error: Engine unavailable or unexpected error.
 * </ul>
 */
public class RestPostKvdbAction extends AbstractCreateAction {

    private static final String ENDPOINT_NAME = "content_manager_kvdb_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_create";

    public RestPostKvdbAction(EngineService engine) {
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
     * @return route configuration for the delete endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.KVDBS_URI)
                        .method(POST)
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
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        RestResponse fieldValidation =
                this.documentValidations.validateRequiredFields(
                        resource, List.of(Constants.KEY_TITLE, Constants.KEY_AUTHOR, "content"));

        if (fieldValidation != null) {
            return fieldValidation;
        }

        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        String spaceError =
                this.documentValidations.validateDocumentInSpace(
                        client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);

        if (spaceError != null) {
            return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());
        }

        return null;
    }

    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        RestResponse engineValidation = this.engine.validateResource(Constants.KEY_KVDB, resource);
        if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    "Engine Validation Failed: " + engineValidation.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    @Override
    protected void linkToParent(Client client, String id, JsonNode root) throws IOException {
        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        this.integrationService.linkResourceToIntegration(integrationId, id, Constants.KEY_KVDBS);
    }
}
