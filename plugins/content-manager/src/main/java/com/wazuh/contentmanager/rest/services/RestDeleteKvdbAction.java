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
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST handler for deleting CTI KVDBs.
 *
 * <p>Endpoint: DELETE /_plugins/_content_manager/kvdbs/{kvdb_id}
 *
 * <p>This handler processes KVDB deletion requests. When a KVDB is deleted, it is also removed from
 * any integrations that reference it.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: KVDB deleted successfully.
 *   <li>400 Bad Request: KVDB ID is missing or invalid.
 *   <li>500 Internal Server Error: Unexpected error during processing or engine unavailable.
 * </ul>
 */
public class RestDeleteKvdbAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_kvdb_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_delete";

    private static final Logger log = LogManager.getLogger(RestDeleteKvdbAction.class);

    private final EngineService engine;
    private PolicyHashService policyHashService;

    /**
     * Constructs a new RestDeleteKvdbAction handler.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestDeleteKvdbAction(EngineService engine) {
        this.engine = engine;
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

    /**
     * Prepares the REST request for processing.
     *
     * @param request the incoming REST request containing the KVDB ID
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
        return channel ->
                channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
    }

    /**
     * Sets the policy hash service for testing purposes.
     *
     * @param policyHashService the PolicyHashService instance to use
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    /**
     * Handles the KVDB deletion request.
     *
     * <p>This method validates the request, ensures the KVDB exists and is in draft space, deletes
     * the KVDB from the index, and removes references to the KVDB from any integrations that include
     * it.
     *
     * @param request the incoming REST request containing the KVDB ID to delete
     * @param client the OpenSearch client for index operations
     * @return a RestResponse indicating success or failure of the deletion
     */
    public RestResponse handleRequest(RestRequest request, Client client) {
        try {
            if (this.engine == null) {
                log.error(Constants.E_ENGINE_IS_NULL);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            String kvdbId = request.param(Constants.KEY_ID);

            // Validate ID is present
            RestResponse validationError =
                    DocumentValidations.validateRequiredParam(kvdbId, Constants.KEY_ID);
            if (validationError != null) {
                return validationError;
            }

            // Validate UUID format
            validationError = DocumentValidations.validateUUID(kvdbId);
            if (validationError != null) {
                return validationError;
            }

            // Ensure Index Exists
            if (!IndexHelper.indexExists(client, Constants.INDEX_KVDBS)) {
                log.error(Constants.E_INDEX_NOT_FOUND, Constants.INDEX_KVDBS);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            ContentIndex kvdbIndex = new ContentIndex(client, Constants.INDEX_KVDBS, null);

            // Check if KVDB exists before deleting
            if (!kvdbIndex.exists(kvdbId)) {
                return new RestResponse(
                        Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
            }

            // Validate KVDB is in draft space
            String spaceValidationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_KVDBS, kvdbId, Constants.KEY_KVDB);
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus());
            }

            // Unlink from Integrations
            ContentUtils.unlinkResourceFromIntegrations(client, kvdbId, Constants.KEY_KVDBS);

            // Delete KVDB
            kvdbIndex.delete(kvdbId);

            // Recalculate policy hashes for draft space
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(kvdbId, RestStatus.OK.getStatus());
        } catch (Exception e) {
            log.error(Constants.E_OPERATION_FAILED, "deleting", Constants.KEY_KVDB, e.getMessage(), e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
