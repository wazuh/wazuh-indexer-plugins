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

import java.util.List;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * REST handler for updating Engine Filters.
 *
 * <p>Endpoint: PUT /_plugins/content-manager/filters/{filter_id}
 *
 * <p>This handler processes filter update requests. The filter is validated against the Wazuh
 * engine before being stored in the index in DRAFT space.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Filter updated successfully after engine validation.
 *   <li>400 Bad Request: Missing or invalid request body, filter ID mismatch, or validation error.
 *   <li>404 Not Found: Filter ID was not found.
 *   <li>500 Internal Server Error: Unexpected error during processing or engine unavailable.
 * </ul>
 */
public class RestPutFilterAction extends AbstractUpdateActionSpaces {

    private static final String ENDPOINT_NAME = "content_manager_filter_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/filter_update";

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);
    private String spaceName = "";

    public RestPutFilterAction(EngineService engine) {
        super(engine);
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
    protected String getSpaceName() {
        return this.spaceName;
    }

    private void setSpaceName(String spaceName) {
        this.spaceName = spaceName;
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the update endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.FILTERS_URI + "/{id}")
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected boolean isDecoder() {
        // Behaves as decoders im terms of how metadata is handled
        return true;
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
}
