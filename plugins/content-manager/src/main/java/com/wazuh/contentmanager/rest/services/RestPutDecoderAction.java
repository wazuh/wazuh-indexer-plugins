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
import java.time.Instant;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * REST handler for updating CTI decoders.
 *
 * <p>Endpoint: PUT /_plugins/content-manager/decoders/{decoder_id}
 *
 * <p>This handler processes decoder update requests. The decoder is validated against the Wazuh
 * engine before being stored in the index with DRAFT space.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Decoder updated successfully after engine validation.
 *   <li>400 Bad Request: Missing or invalid request body, decoder ID mismatch, or validation error.
 *   <li>500 Internal Server Error: Unexpected error during processing or engine unavailable.
 * </ul>
 */
public class RestPutDecoderAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutDecoderAction.class);

    private static final String ENDPOINT_NAME = "content_manager_decoder_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_update";

    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Constructs a new RestPutDecoderAction handler.
     *
     * @param engine the engine service instance for communication with the Wazuh engine
     */
    public RestPutDecoderAction(EngineService engine) {
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
        return channel ->
                channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
    }

    /**
     * Handles the decoder update request.
     *
     * <p>This method validates the request payload, ensures the decoder ID matches, validates the
     * decoder with the Wazuh engine, and stores the updated decoder in the index.
     *
     * @param request the incoming REST request containing the decoder data to update
     * @param client the OpenSearch client for index operations
     * @return a RestResponse indicating success or failure of the update
     */
    public RestResponse handleRequest(RestRequest request, Client client) {
        // Validate prerequisites
        RestResponse validationError = this.validatePrerequisites(request);
        if (validationError != null) {
            return validationError;
        }

        try {
            String decoderId = this.extractDecoderId(request);
            if (decoderId == null || decoderId.isBlank()) {
                return new RestResponse("Decoder ID is required.", RestStatus.BAD_REQUEST.getStatus());
            }

            JsonNode payload = this.mapper.readTree(request.content().streamInput());
            // Validate payload structure
            validationError = this.validatePayload(payload, decoderId);
            if (validationError != null) {
                return validationError;
            }

            ObjectNode resourceNode = (ObjectNode) payload.get(Constants.KEY_RESOURCE);
            resourceNode.put(Constants.KEY_ID, decoderId);

            // Validate decoder is in draft space
            String spaceValidationError =
                    DocumentValidations.validateDocumentInSpace(client, Constants.INDEX_DECODERS, decoderId, Constants.KEY_DECODER);
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus());
            }

            // Update the modified timestamp
            this.updateTimestampMetadata(resourceNode);

            // Validate decoder with Wazuh Engine
            ObjectNode enginePayload = mapper.createObjectNode();
            enginePayload.set(Constants.KEY_RESOURCE, resourceNode);
            enginePayload.put(Constants.KEY_TYPE, Constants.KEY_DECODER);
            final RestResponse engineValidation = this.engine.validate(enginePayload);
            if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
                return new RestResponse(engineValidation.getMessage(), engineValidation.getStatus());
            }

            // Update decoder
            this.updateDecoder(client, decoderId, resourceNode);

            // Regenerate space hash because decoder content changed
            this.regenerateSpaceHash(client, Space.DRAFT.toString());

            return new RestResponse(
                    "Decoder updated successfully with ID: " + decoderId, RestStatus.OK.getStatus());

        } catch (IOException e) {
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            log.error("Error updating decoder: {}", e.getMessage(), e);
            return new RestResponse(
                    e.getMessage() != null ? e.getMessage() : "An unexpected error occurred.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /** Validates that the engine service and request content are available. */
    private RestResponse validatePrerequisites(RestRequest request) {
        if (this.engine == null) {
            return new RestResponse(
                    "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
        if (!request.hasContent()) {
            return new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /** Extracts the decoder ID from the request path parameters. */
    private String extractDecoderId(RestRequest request) {
        return request.param(Constants.KEY_ID);
    }

    /** Validates the payload structure and required fields. */
    private RestResponse validatePayload(JsonNode payload, String decoderId) {
        if (!payload.has(Constants.KEY_RESOURCE) || !payload.get(Constants.KEY_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        ObjectNode resourceNode = (ObjectNode) payload.get(Constants.KEY_RESOURCE);
        if (resourceNode.hasNonNull(Constants.KEY_ID)) {
            String payloadId = resourceNode.get(Constants.KEY_ID).asText();
            if (!payloadId.equals(decoderId)) {
                return new RestResponse(
                        "Decoder ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }

    /** Updates the decoder document in the index. */
    private void updateDecoder(Client client, String decoderId, ObjectNode resourceNode)
            throws IOException {

        RestPutDecoderAction.ensureIndexExists(client);
        ContentIndex decoderIndex = new ContentIndex(client, Constants.INDEX_DECODERS, null);

        // Check if decoder exists before updating
        if (!decoderIndex.exists(decoderId)) {
            throw new IOException("Decoder [" + decoderId + "] not found.");
        }

        decoderIndex.create(decoderId, this.buildDecoderPayload(resourceNode));
    }

    /** Builds the decoder payload with document and space information. */
    private JsonNode buildDecoderPayload(ObjectNode resourceNode) {
        ObjectNode node = this.mapper.createObjectNode();
        node.put(Constants.KEY_TYPE, Constants.KEY_DECODERS);
        node.set(Constants.KEY_DOCUMENT, resourceNode);
        // Add draft space
        ObjectNode spaceNode = this.mapper.createObjectNode();
        spaceNode.put(Constants.KEY_NAME, Space.DRAFT.toString());
        node.set(Constants.KEY_SPACE, spaceNode);

        return node;
    }

    /** Ensures the decoder index exists, creating it if necessary. */
    private static void ensureIndexExists(Client client) throws IOException {
        if (!IndexHelper.indexExists(client, Constants.INDEX_DECODERS)) {
            ContentIndex index = new ContentIndex(client, Constants.INDEX_DECODERS, null);
            try {
                index.createIndex();
            } catch (Exception e) {
                throw new IOException("Failed to create index " + Constants.INDEX_DECODERS, e);
            }
        }
    }

    /**
     * Regenerates the space hash.
     *
     * @param client the OpenSearch client
     * @param spaceName the name of the space to regenerate hash for
     */
    private void regenerateSpaceHash(Client client, String spaceName) {
        PolicyHashService policyHashService = new PolicyHashService(client);

        // Use PolicyHashService to recalculate space hash for the given space
        policyHashService.calculateAndUpdate(List.of(spaceName));

        log.debug("Regenerated space hash for space={}", spaceName);
    }

    /**
     * Updates the modified timestamp in the resource node metadata.
     *
     * @param resourceNode the resource node to update
     */
    private void updateTimestampMetadata(ObjectNode resourceNode) {
        String currentTimestamp = Instant.now().toString();

        // Ensure metadata node exists
        ObjectNode metadataNode;
        if (resourceNode.has(Constants.KEY_METADATA) && resourceNode.get(Constants.KEY_METADATA).isObject()) {
            metadataNode = (ObjectNode) resourceNode.get(Constants.KEY_METADATA);
        } else {
            metadataNode = this.mapper.createObjectNode();
            resourceNode.set(Constants.KEY_METADATA, metadataNode);
        }

        // Ensure author node exists
        ObjectNode authorNode;
        if (metadataNode.has(Constants.KEY_AUTHOR) && metadataNode.get(Constants.KEY_AUTHOR).isObject()) {
            authorNode = (ObjectNode) metadataNode.get(Constants.KEY_AUTHOR);
        } else {
            authorNode = this.mapper.createObjectNode();
            metadataNode.set(Constants.KEY_AUTHOR, authorNode);
        }

        // Set modified timestamp
        authorNode.put(Constants.KEY_MODIFIED, currentTimestamp);
    }
}
