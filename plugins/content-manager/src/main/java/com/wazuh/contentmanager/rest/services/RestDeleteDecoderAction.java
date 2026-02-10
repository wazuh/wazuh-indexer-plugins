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
import java.util.Locale;

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
 * REST handler for deleting CTI decoders.
 *
 * <p>Endpoint: DELETE /_plugins/content-manager/decoder/{decoder_id}
 *
 * <p>This handler processes decoder deletion requests. When a decoder is deleted, it is also
 * removed from any integrations that reference it.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Decoder deleted successfully.
 *   <li>400 Bad Request: Decoder ID is missing or invalid.
 *   <li>500 Internal Server Error: Unexpected error during processing or engine unavailable.
 * </ul>
 */
public class RestDeleteDecoderAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestDeleteDecoderAction.class);

    private static final String ENDPOINT_NAME = "content_manager_decoder_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_delete";

    private final EngineService engine;
    private PolicyHashService policyHashService;

    /**
     * Constructs a new RestDeleteDecoderAction handler.
     *
     * @param engine the engine service instance for communication with the Wazuh engine
     */
    public RestDeleteDecoderAction(EngineService engine) {
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
     * @return route configuration for the update endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.DECODERS_URI + "/{id}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the REST request for processing.
     *
     * @param request the incoming REST request containing the decoder ID
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
     * Sets the policy hash service for testing purposes.
     *
     * @param policyHashService the PolicyHashService instance to use
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    /**
     * Handles the decoder deletion request.
     *
     * <p>This method validates the request, deletes the decoder from the index, and removes
     * references to the decoder from any integrations that include it.
     *
     * @param request the incoming REST request containing the decoder ID to delete
     * @param client the OpenSearch client for index operations
     * @return a BytesRestResponse indicating success or failure of the deletion
     */
    public BytesRestResponse handleRequest(RestRequest request, Client client) {
        try {
            if (this.engine == null) {
                log.error("Engine service not initialized");
                return new RestResponse(
                                Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                        .toBytesRestResponse();
            }

            String decoderId = request.param(Constants.KEY_ID);

            // Validate ID is present
            if (decoderId == null || decoderId.isBlank()) {
                return new RestResponse(
                                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_ID),
                                RestStatus.BAD_REQUEST.getStatus())
                        .toBytesRestResponse();
            }

            // Validate UUID format
            RestResponse uuidValidation = DocumentValidations.validateUUID(decoderId);
            if (uuidValidation != null) {
                return uuidValidation.toBytesRestResponse();
            }

            // Ensure Index Exists
            if (!IndexHelper.indexExists(client, Constants.INDEX_DECODERS)) {
                log.error("Decoder index not found");
                return new RestResponse(
                                Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                        .toBytesRestResponse();
            }

            ContentIndex decoderIndex = new ContentIndex(client, Constants.INDEX_DECODERS, null);

            // Check if decoder exists before deleting
            if (!decoderIndex.exists(decoderId)) {
                return new RestResponse(
                                Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus())
                        .toBytesRestResponse();
            }

            // Validate decoder is in draft space
            String spaceValidationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_DECODERS, decoderId, Constants.KEY_DECODER);
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus())
                        .toBytesRestResponse();
            }

            // Unlink from Integrations
            ContentUtils.unlinkResourceFromIntegrations(client, decoderId, Constants.KEY_DECODERS);

            // Delete
            decoderIndex.delete(decoderId);

            // Regenerate space hash because decoder was removed from space
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(decoderId, RestStatus.OK.getStatus()).toBytesRestResponse();
        } catch (Exception e) {
            log.error("Error deleting decoder: {}", e.getMessage(), e);
            return new RestResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                    .toBytesRestResponse();
        }
    }
}
