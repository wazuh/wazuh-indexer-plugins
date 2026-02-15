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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.NamedRoute;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * PUT /_plugins/content-manager/integrations/{id}
 *
 * <p>Updates an existing integration in the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The integration exists and is in the draft space.
 *   <li>The request body contains all mandatory fields (title, author, category).
 *   <li>The lists of linked resources (Rules, Decoders, KVDBs) match the existing document (they
 *       cannot be modified via this endpoint).
 *   <li>Immutable metadata (creation date) is preserved from the existing document.
 *   <li>The updated integration is synchronized with the Security Analytics Plugin (SAP).
 *   <li>The updated integration payload is validated by the Engine.
 *   <li>The integration is re-indexed and the space hash is recalculated.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Integration updated successfully.
 *   <li>400 Bad Request: Missing fields, invalid payload, or attempt to modify linked resource
 *       lists.
 *   <li>404 Not Found: Integration with specified ID was not found.
 *   <li>500 Internal Server Error: Unexpected error during processing or external service failure.
 * </ul>
 */
public class RestPutIntegrationAction extends AbstractUpdateAction {

    private static final String ENDPOINT_NAME = "content_manager_integration_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_update";

    public RestPutIntegrationAction(EngineService engine) {
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
     * @return route configuration for the update endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.INTEGRATIONS_URI + "/{id}")
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_INTEGRATIONS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_INTEGRATION;
    }

    /** Preserves metadata and validates that linked resource lists have not changed. */
    @Override
    protected RestResponse preserveMetadata(ContentIndex index, String id, ObjectNode resourceNode) {
        RestResponse response = super.preserveMetadata(index, id, resourceNode);
        if (response != null) {
            return response;
        }

        JsonNode existingDoc = index.getDocument(id);
        if (existingDoc != null && existingDoc.has(Constants.KEY_DOCUMENT)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> existing =
                    MAPPER.convertValue(existingDoc.get(Constants.KEY_DOCUMENT), Map.class);

            RestResponse error;
            error = checkListEquality(existing, resourceNode, Constants.KEY_RULES);
            if (error != null) return error;

            error = checkListEquality(existing, resourceNode, Constants.KEY_DECODERS);
            if (error != null) return error;

            error = checkListEquality(existing, resourceNode, Constants.KEY_KVDBS);
            if (error != null) return error;
        }
        return null;
    }

    /**
     * Checks if two lists are equal ot not, if not it returns a RestResponse with the error
     *
     * @param existing Current document
     * @param resource New document
     * @param key Key of the list to check if is equal or not
     */
    private RestResponse checkListEquality(
            Map<String, Object> existing, JsonNode resource, String key) {
        @SuppressWarnings("unchecked")
        List<String> oldList = (List<String>) existing.getOrDefault(key, Collections.emptyList());
        List<String> newList = ContentUtils.extractStringList(resource, key);
        return ContentUtils.validateListEquality(oldList, newList, key);
    }

    @Override
    protected RestResponse validatePayload(JsonNode root, JsonNode resource) {
        return ContentUtils.validateRequiredFields(
                resource,
                List.of(
                        Constants.KEY_TITLE,
                        Constants.KEY_AUTHOR,
                        Constants.KEY_CATEGORY,
                        Constants.KEY_DESCRIPTION,
                        "documentation"));
    }

    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        // 1. Engine Validate
        ObjectNode enginePayload = MAPPER.createObjectNode();
        enginePayload.set(Constants.KEY_RESOURCE, resource);
        enginePayload.put(Constants.KEY_TYPE, Constants.KEY_INTEGRATION);

        RestResponse engineResponse = this.engine.validate(enginePayload);
        if (engineResponse.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    "Engine Validation Failed: " + engineResponse.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // 2. SAP Upsert
        try {
            this.securityAnalyticsService.upsertIntegration(resource, Space.DRAFT, PUT);
        } catch (Exception e) {
            return new RestResponse(
                    "SAP Upsert Error: " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        return null;
    }
}
