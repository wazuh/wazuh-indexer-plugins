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
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

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
    // TODO: Move to a common constants class
    private static final String ENDPOINT_NAME = "content_manager_decoder_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_update";
    private static final String INDEX_ID_PREFIX = "d_";
    private static final String DECODER_INDEX = ".cti-decoders";
    private static final String DECODER_TYPE = "decoder";
    private static final String FIELD_RESOURCE = "resource";
    private static final String FIELD_ID = "id";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_SPACE = "space";
    private static final String FIELD_NAME = "name";
    private static final String FIELD_METADATA = "metadata";
    private static final String FIELD_AUTHOR = "author";
    private static final String FIELD_MODIFIED = "modified";
    private static final String FIELD_DATE = "date";
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
        request.param("id");
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

            ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
            String resourceId = RestPutDecoderAction.toResourceId(decoderId);
            resourceNode.put(FIELD_ID, resourceId);

            // Preserve metadata from existing document and update modified timestamp
            this.preserveMetadataAndUpdateTimestamp(client, decoderId, resourceNode);

            // Validate with engine
            RestResponse engineResponse = this.validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }

            // Update decoder
            this.updateDecoder(client, decoderId, resourceNode);

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
        String decoderId = request.param("id");
        if (decoderId == null || decoderId.isBlank()) {
            decoderId = request.param("decoder_id");
        }
        return decoderId;
    }

    /** Validates the payload structure and required fields. */
    private RestResponse validatePayload(JsonNode payload, String decoderId) {
        if (!payload.has(FIELD_RESOURCE) || !payload.get(FIELD_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
        String resourceId = RestPutDecoderAction.toResourceId(decoderId);
        if (resourceNode.hasNonNull(FIELD_ID)) {
            String payloadId = resourceNode.get(FIELD_ID).asText();
            if (!payloadId.equals(resourceId) && !payloadId.equals(decoderId)) {
                return new RestResponse(
                        "Decoder ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }

    /** Validates the resource with the engine service. */
    private RestResponse validateWithEngine(ObjectNode resourceNode) {
        ObjectNode enginePayload = this.mapper.createObjectNode();
        enginePayload.put(FIELD_TYPE, DECODER_TYPE);
        enginePayload.set(FIELD_RESOURCE, resourceNode);

        RestResponse response = this.engine.validate(enginePayload);
        if (response == null) {
            return new RestResponse(
                    "Invalid decoder body, engine validation failed.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /** Updates the decoder document in the index. */
    private void updateDecoder(Client client, String decoderId, ObjectNode resourceNode)
            throws IOException {

        RestPutDecoderAction.ensureIndexExists(client);
        ContentIndex decoderIndex = new ContentIndex(client, DECODER_INDEX, null);

        // Check if decoder exists before updating
        if (!decoderIndex.exists(decoderId)) {
            throw new IOException("Decoder [" + decoderId + "] not found.");
        }

        decoderIndex.create(decoderId, this.buildDecoderPayload(resourceNode));
    }

    /** Builds the decoder payload with document and space information. */
    private JsonNode buildDecoderPayload(ObjectNode resourceNode) {
        ObjectNode node = this.mapper.createObjectNode();
        node.put(FIELD_TYPE, DECODER_TYPE);
        node.set(FIELD_DOCUMENT, resourceNode);
        // Add draft space
        ObjectNode spaceNode = this.mapper.createObjectNode();
        spaceNode.put(FIELD_NAME, Space.DRAFT.toString());
        node.set(FIELD_SPACE, spaceNode);

        return node;
    }

    /** Ensures the decoder index exists, creating it if necessary. */
    private static void ensureIndexExists(Client client) throws IOException {
        if (!IndexHelper.indexExists(client, RestPutDecoderAction.DECODER_INDEX)) {
            ContentIndex index = new ContentIndex(client, RestPutDecoderAction.DECODER_INDEX, null);
            try {
                index.createIndex();
            } catch (Exception e) {
                throw new IOException("Failed to create index " + RestPutDecoderAction.DECODER_INDEX, e);
            }
        }
    }

    /** Converts an index document ID to a resource ID by removing the prefix. */
    private static String toResourceId(String indexId) {
        if (indexId != null && indexId.startsWith(INDEX_ID_PREFIX)) {
            return indexId.substring(INDEX_ID_PREFIX.length());
        }
        return indexId;
    }

    /**
     * Preserves only the date field from existing metadata and allows other metadata fields to be updated.
     * The metadata.author.date is preserved from the existing document and cannot be modified.
     * All other metadata fields (title, description, author.name) can be updated from the request.
     * The metadata.author.modified timestamp is always updated to the current time.
     *
     * @param client the OpenSearch client
     * @param decoderId the decoder ID
     * @param resourceNode the resource node to update
     * @throws IOException if an error occurs retrieving the existing document
     */
    private void preserveMetadataAndUpdateTimestamp(Client client, String decoderId, ObjectNode resourceNode)
            throws IOException {
        RestPutDecoderAction.ensureIndexExists(client);
        ContentIndex decoderIndex = new ContentIndex(client, DECODER_INDEX, null);

        // Get existing document
        JsonNode existingDocument = decoderIndex.getDocument(decoderId);
        if (existingDocument == null) {
            throw new IOException("Decoder [" + decoderId + "] not found.");
        }

        // Extract existing metadata from document.metadata
        JsonNode existingMetadata = null;
        String preservedDate = null;
        if (existingDocument.has(FIELD_DOCUMENT) && existingDocument.get(FIELD_DOCUMENT).isObject()) {
            JsonNode existingDoc = existingDocument.get(FIELD_DOCUMENT);
            if (existingDoc.has(FIELD_METADATA) && existingDoc.get(FIELD_METADATA).isObject()) {
                existingMetadata = existingDoc.get(FIELD_METADATA);
                // Extract the date from existing metadata.author.date
                if (existingMetadata.has(FIELD_AUTHOR) && existingMetadata.get(FIELD_AUTHOR).isObject()) {
                    JsonNode existingAuthor = existingMetadata.get(FIELD_AUTHOR);
                    if (existingAuthor.has(FIELD_DATE)) {
                        preservedDate = existingAuthor.get(FIELD_DATE).asText();
                    }
                }
            }
        }

        // Get metadata from request (if provided)
        ObjectNode requestMetadata = null;
        if (resourceNode.has(FIELD_METADATA) && resourceNode.get(FIELD_METADATA).isObject()) {
            requestMetadata = (ObjectNode) resourceNode.get(FIELD_METADATA);
        }

        // Build the final metadata object
        ObjectNode finalMetadata;
        if (requestMetadata != null) {
            // Start with metadata from request (allows updates to title, description, author.name, etc.)
            finalMetadata = (ObjectNode) this.mapper.readTree(
                    this.mapper.writeValueAsString(requestMetadata));
        } else if (existingMetadata != null) {
            // If no metadata in request, start with existing metadata
            finalMetadata = (ObjectNode) this.mapper.readTree(
                    this.mapper.writeValueAsString(existingMetadata));
        } else {
            // If no existing metadata and no request metadata, create new
            finalMetadata = this.mapper.createObjectNode();
        }

        // Ensure author node exists
        ObjectNode authorNode;
        if (finalMetadata.has(FIELD_AUTHOR) && finalMetadata.get(FIELD_AUTHOR).isObject()) {
            authorNode = (ObjectNode) finalMetadata.get(FIELD_AUTHOR);
        } else {
            authorNode = this.mapper.createObjectNode();
            finalMetadata.set(FIELD_AUTHOR, authorNode);
        }

        // Preserve the date from existing document (if it exists)
        if (preservedDate != null) {
            authorNode.put(FIELD_DATE, preservedDate);
        }

        // Always update modified timestamp
        authorNode.put(FIELD_MODIFIED, Instant.now().toString());

        // Set the final metadata in resourceNode
        resourceNode.set(FIELD_METADATA, finalMetadata);
    }
}
