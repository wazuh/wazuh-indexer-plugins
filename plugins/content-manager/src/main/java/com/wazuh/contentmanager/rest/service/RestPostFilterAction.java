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

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for creating Engine Filter resources.
 *
 * <p>Endpoint: POST /_plugins/_content_manager/filters
 *
 * <p>Creates a filter in the draft space.
 *
 * <p>HTTP responses:
 *
 * <ul>
 *   <li>201 Created: filter created successfully.
 *   <li>400 Bad Request: Invalid payload or validation error.
 *   <li>500 Internal Server Error: Engine unavailable or unexpected error.
 * </ul>
 */
public class RestPostFilterAction extends AbstractCreateActionSpaces {

    private static final String ENDPOINT_NAME = "content_manager_filter_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/filter_create";

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);
    private String spaceName = "";

    /**
     * Constructs a new RestPostFilterAction handler.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPostFilterAction(EngineService engine) {
        super(engine);
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the create endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.FILTERS_URI)
                        .method(POST)
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
    protected boolean requiresIntegrationId() {
        return false;
    }

    @Override
    protected boolean isDecoder() {
        // Behaves as decoders im terms of how metadata is handled
        return true;
    }

    @Override
    protected String getSpaceName() {
        return this.spaceName;
    }

    private void setSpaceName(String spaceName) {
        this.spaceName = spaceName;
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        // Validate space is either draft or standard.
        String spaceName = root.path(Constants.KEY_SPACE).asText(null);

        if (!isValidSpace(spaceName)) {
            return createInvalidSpaceResponse();
        }
        setSpaceName(spaceName);
        return null;
    }

    /**
     * Checks if the provided space value is valid.
     *
     * @param spaceValue the space value to validate
     * @return true if the space value is valid, false otherwise
     */
    private boolean isValidSpace(String spaceValue) {
        if (spaceValue == null) {
            return false;
        }

        try {
            return validSpaces.contains(Space.fromValue(spaceValue));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Creates an error response for invalid space values.
     *
     * @return RestResponse with error message and bad request status
     */
    private RestResponse createInvalidSpaceResponse() {
        return new RestResponse(
                "Invalid space value. Must be one of: " + validSpaces, RestStatus.BAD_REQUEST.getStatus());
    }

    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        RestResponse engineValidation = this.engine.validateResource(Constants.KEY_FILTER, resource);
        if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    "Engine Validation Failed: " + engineValidation.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    @Override
    protected void linkToParent(Client client, String id, JsonNode root) throws IOException {
        // Not applicable for this implementation.
    }
}
