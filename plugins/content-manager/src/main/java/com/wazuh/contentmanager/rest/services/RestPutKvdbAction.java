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
import org.opensearch.OpenSearchParseException;
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
import static com.wazuh.contentmanager.utils.Constants.INDEX_KVDBS;

/**
 * REST handler for updating CTI KVDBs.
 *
 * <p>Endpoint: PUT /_plugins/content-manager/kvdbs/{kvdb_id}
 *
 * <p>This handler processes KVDB update requests. The KVDB is validated against the Wazuh engine
 * before being stored in the index with DRAFT space.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: KVDB updated successfully after engine validation.
 *   <li>400 Bad Request: Missing or invalid request body, KVDB ID mismatch, or validation error.
 *   <li>500 Internal Server Error: Unexpected error during processing or engine unavailable.
 * </ul>
 */
public class RestPutKvdbAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutKvdbAction.class);
    private static final String ENDPOINT_NAME = "content_manager_kvdb_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_update";

    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();
    private PolicyHashService policyHashService;

    /**
     * Constructs a new RestPutKvdbAction handler.
     *
     * @param engine the engine service instance for communication with the Wazuh engine
     */
    public RestPutKvdbAction(EngineService engine) {
        this.engine = engine;
    }

    /**
     * Setter for the policy hash service, used in tests.
     *
     * @param policyHashService the policy hash service to set
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
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
                        .path(PluginSettings.KVDBS_URI + "/{id}")
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
     * Handles the KVDB update request.
     *
     * <p>This method validates the request payload, ensures the KVDB ID matches, validates the KVDB
     * with the Wazuh engine, and stores the updated KVDB in the index.
     *
     * @param request the incoming REST request containing the KVDB data to update
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
            String kvdbId = request.param(Constants.KEY_ID);
            if (kvdbId == null || kvdbId.isBlank()) {
                return new RestResponse("KVDB ID is required.", RestStatus.BAD_REQUEST.getStatus());
            }

            JsonNode payload = this.mapper.readTree(request.content().streamInput());

            // Validate payload structure
            validationError = DocumentValidations.validateResourcePayload(payload, kvdbId, false);
            if (validationError != null) {
                return validationError;
            }

            ObjectNode resourceNode = (ObjectNode) payload.get(Constants.KEY_RESOURCE);
            resourceNode.put(Constants.KEY_ID, kvdbId);

            // Update timestamps
            ContentUtils.updateTimestampMetadata(resourceNode, false);

            // Validate with engine
            RestResponse engineResponse = this.validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }

            // Validate KVDB exists and is in draft space
            RestResponse validationResponse =
                    DocumentValidations.validateDocumentInSpaceWithResponse(
                            client, INDEX_KVDBS, kvdbId, Constants.KEY_KVDB);
            if (validationResponse != null) {
                return validationResponse;
            }

            // Update KVDB
            this.updateKvdb(client, kvdbId, resourceNode);

            // Regenerate space hash because KVDB content changed
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(
                    "KVDB updated successfully with ID: " + kvdbId, RestStatus.OK.getStatus());

        } catch (IOException e) {
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (OpenSearchParseException e) {
            log.error("Error updating KVDB: {}", e.getMessage(), e);
            return new RestResponse(
                    e.getMessage() != null ? e.getMessage() : "An unexpected error occurred.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /** Validates the resource with the engine service. */
    private RestResponse validateWithEngine(ObjectNode resourceNode) {
        ObjectNode enginePayload = this.mapper.createObjectNode();
        enginePayload.put(Constants.KEY_TYPE, Constants.KEY_KVDB);
        enginePayload.set(Constants.KEY_RESOURCE, resourceNode);

        RestResponse response = this.engine.validate(enginePayload);
        if (response.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(response.getMessage(), response.getStatus());
        }
        return null;
    }

    /** Updates the KVDB document in the index. */
    private void updateKvdb(Client client, String kvdbId, ObjectNode resourceNode)
            throws IOException {
        try {
            ContentIndex kvdbIndex = new ContentIndex(client, INDEX_KVDBS, null);

            // Check if KVDB exists before updating
            if (!kvdbIndex.exists(kvdbId)) {
                throw new IOException("KVDB [" + kvdbId + "] not found.");
            }

            kvdbIndex.create(kvdbId, this.buildKvdbPayload(resourceNode));
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /** Builds the KVDB payload with document and space information. */
    private JsonNode buildKvdbPayload(ObjectNode resourceNode) {
        ObjectNode node = this.mapper.createObjectNode();
        node.put(Constants.KEY_TYPE, Constants.KEY_KVDB);
        node.set(Constants.KEY_DOCUMENT, resourceNode);
        // Add draft space
        ObjectNode spaceNode = this.mapper.createObjectNode();
        spaceNode.put(Constants.KEY_NAME, Space.DRAFT.toString());
        node.set(Constants.KEY_SPACE, spaceNode);

        return node;
    }
}
