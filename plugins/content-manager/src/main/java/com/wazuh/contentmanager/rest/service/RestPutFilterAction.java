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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;
import com.wazuh.contentmanager.utils.DocumentValidations;

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
public class RestPutFilterAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutFilterAction.class);

    private static final String ENDPOINT_NAME = "content_manager_filter_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/filter_update";

    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();
    private PolicyHashService policyHashService;

    /**
     * Constructs a new RestPutFilterAction handler.
     *
     * @param engine the engine service instance for communication with the Wazuh engine
     */
    public RestPutFilterAction(EngineService engine) {
        this.engine = engine;
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

    /**
     * Prepares the REST request for processing.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        // Consume path params early to avoid unrecognized parameter errors.
        request.param(Constants.KEY_ID);
        this.policyHashService = new PolicyHashService(client);
        return channel ->
                channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
    }

    /**
     * Sets the policy hash service.
     *
     * @param policyHashService The service responsible for calculating policy hashes.
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    /**
     * Handles the filter update request.
     *
     * <p>This method validates the request payload, ensures the filter ID matches, validates the
     * filter with the Wazuh engine, and stores the updated filter in the index.
     *
     * @param request the incoming REST request containing the filter data to update
     * @param client the OpenSearch client for index operations
     * @return a RestResponse indicating success or failure of the update
     */
    public RestResponse handleRequest(RestRequest request, Client client) {
        // Validate prerequisites
        RestResponse validationError = DocumentValidations.validatePrerequisites(this.engine, request);
        if (validationError != null) {
            return validationError;
        }

        try {
            String filterId = request.param(Constants.KEY_ID);
            if (filterId == null || filterId.isBlank()) {
                return new RestResponse("Filter ID is required.", RestStatus.BAD_REQUEST.getStatus());
            }

            JsonNode payload = this.mapper.readTree(request.content().streamInput());

            // Validate payload structure
            validationError = DocumentValidations.validateResourcePayload(payload, filterId, false);
            if (validationError != null) {
                return validationError;
            }

            ObjectNode resourceNode = (ObjectNode) payload.get(Constants.KEY_RESOURCE);
            resourceNode.put(Constants.KEY_ID, filterId);

            // Validate forbidden metadata fields
            validationError = ContentUtils.validateMetadataFields(resourceNode, false);
            if (validationError != null) {
                return validationError;
            }

            // Validate filter is in draft or standard spaces
            List<Space> spaces = List.of(Space.DRAFT, Space.STANDARD);
            String spaceValidationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_FILTERS, filterId, Constants.KEY_FILTER, spaces);
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus());
            }

            // Fetch existing filter to preserve creation date
            ContentIndex filterIndex = new ContentIndex(client, Constants.INDEX_FILTERS, null);
            JsonNode existingDoc = filterIndex.getDocument(filterId);
            if (existingDoc == null) {
                return new RestResponse(
                        "Filter [" + filterId + "] not found.", RestStatus.NOT_FOUND.getStatus());
            }

            String existingDate = null;
            if (existingDoc.has(Constants.KEY_DOCUMENT)) {
                JsonNode doc = existingDoc.get(Constants.KEY_DOCUMENT);
                if (doc.has(Constants.KEY_METADATA)) {
                    JsonNode meta = doc.get(Constants.KEY_METADATA);
                    if (meta.has(Constants.KEY_AUTHOR)) {
                        JsonNode auth = meta.get(Constants.KEY_AUTHOR);
                        if (auth.has(Constants.KEY_DATE)) {
                            existingDate = auth.get(Constants.KEY_DATE).asText();
                        }
                    }
                }
            }

            // Update timestamp
            ContentUtils.updateTimestampMetadata(resourceNode, false, false);
            ((ObjectNode) resourceNode.get(Constants.KEY_METADATA).get(Constants.KEY_AUTHOR))
                    .put(Constants.KEY_DATE, existingDate);

            // Validate filter with Wazuh Engine
            RestResponse engineValidation =
                    this.engine.validateResource(Constants.KEY_FILTER, resourceNode);
            if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
                return new RestResponse(engineValidation.getMessage(), engineValidation.getStatus());
            }

            // Update filter
            String spaceName = String.valueOf(existingDoc.get(Constants.KEY_SPACE));
            filterIndex.create(filterId, ContentUtils.buildCtiWrapper(resourceNode, spaceName));

            // Regenerate space hash because filter content changed
            this.policyHashService.calculateAndUpdate(List.of(spaceName));

            return new RestResponse(
                    "Filter updated successfully with ID: " + filterId, RestStatus.OK.getStatus());

        } catch (IOException e) {
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            log.error("Error updating filter: {}", e.getMessage(), e);
            return new RestResponse(
                    e.getMessage() != null ? e.getMessage() : "An unexpected error occurred.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
