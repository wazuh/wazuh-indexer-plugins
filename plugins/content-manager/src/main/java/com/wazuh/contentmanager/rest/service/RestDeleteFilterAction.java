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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.DocumentValidations;

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
public class RestDeleteFilterAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestDeleteFilterAction.class);

    private static final String ENDPOINT_NAME = "content_manager_filter_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/filter_delete";

    private PolicyHashService policyHashService;

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

    /**
     * Prepares the REST request for processing.
     *
     * @param request the incoming REST request containing the filter ID
     * @param client the node client for executing operations
     * @return a consumer that executes the delete operation and sends the response
     * @throws IOException if an I/O error occurs during request preparation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        // Consume path params early to avoid unrecognized parameter errors.
        request.param(Constants.KEY_ID);
        this.policyHashService = new PolicyHashService(client);
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /**
     * Handles the filter deletion request.
     *
     * <p>This method validates the request, deletes the filter from the index, and removes references
     * to the filter from any integrations that include it.
     *
     * @param request the incoming REST request containing the filter ID to delete
     * @param client the OpenSearch client for index operations
     * @return a BytesRestResponse indicating success or failure of the deletion
     */
    public BytesRestResponse handleRequest(RestRequest request, Client client) {
        try {
            String filterId = request.param(Constants.KEY_ID);
            if (filterId == null || filterId.isBlank()) {
                return new RestResponse("Filter ID is required.", RestStatus.BAD_REQUEST.getStatus())
                        .toBytesRestResponse();
            }

            // Ensure Index Exists
            if (!IndexHelper.indexExists(client, Constants.INDEX_FILTERS)) {
                return new RestResponse("Filter index not found.", RestStatus.NOT_FOUND.getStatus())
                        .toBytesRestResponse();
            }

            // Validate filter is in draft space
            String validationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_FILTERS, filterId, Constants.KEY_FILTERS);
            if (validationError != null) {
                return new RestResponse(validationError, RestStatus.BAD_REQUEST.getStatus())
                        .toBytesRestResponse();
            }

            ContentIndex filterIndex = new ContentIndex(client, Constants.INDEX_FILTERS, null);

            // Check if filter exists before deleting
            if (!filterIndex.exists(filterId)) {
                return new RestResponse(
                                "Filter [" + filterId + "] not found.", RestStatus.NOT_FOUND.getStatus())
                        .toBytesRestResponse();
            }

            // Delete
            filterIndex.delete(filterId);

            // Regenerate space hash because filter was removed from space
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse("Filter deleted successfully.", RestStatus.OK.getStatus())
                    .toBytesRestResponse();
        } catch (Exception e) {
            log.error("Error deleting filter: {}", e.getMessage(), e);
            return new RestResponse(
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : "An unexpected error occurred while processing your request.",
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                    .toBytesRestResponse();
        }
    }

    /**
     * Sets the policy hash service for testing purposes.
     *
     * @param policyHashService the PolicyHashService instance to use
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }
}
