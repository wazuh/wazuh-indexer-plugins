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
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.PUT;
import static com.wazuh.contentmanager.utils.Constants.INDEX_DECODERS;
import static com.wazuh.contentmanager.utils.Constants.KEY_DOCUMENT;

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
    private static final String FIELD_RESOURCE = "resource";
    private static final String FIELD_ID = "id";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_METADATA = "metadata";
    private static final String FIELD_AUTHOR = "author";
    private static final String FIELD_DATE = "date";
    private static final String FIELD_MODIFIED = "modified";
    private static final String DECODER_TYPE = "decoder";
    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();
    private ContentIndex decoderIndex;

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
        this.decoderIndex = new ContentIndex(client, INDEX_DECODERS, null);
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
            String resourceId = this.toResourceId(decoderId);
            resourceNode.put(FIELD_ID, resourceId);

            // Validate decoder is in draft space
            String spaceValidationError =
                    DocumentValidations.validateDocumentInSpace(client, INDEX_DECODERS, decoderId, "Decoder");
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus());
            }

            this.ensureIndexExists(client);
            this.preserveMetadataAndUpdateTimestamp(decoderId, resourceNode);

            // Validate decoder with Wazuh Engine
            ObjectNode enginePayload = this.mapper.createObjectNode();
            enginePayload.set("resource", resourceNode);
            enginePayload.put("type", "decoder");
            final RestResponse engineValidation = this.engine.validate(enginePayload);
            if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
                return new RestResponse(engineValidation.getMessage(), engineValidation.getStatus());
            }

            // Update decoder
            this.updateDecoder(decoderId, resourceNode);

            return new RestResponse(
                    "Decoder updated successfully with ID: " + decoderId, RestStatus.OK.getStatus());

        } catch (IOException e) {
            String errorMessage = e.getMessage();
            if (errorMessage != null
                    && errorMessage.contains("Document [")
                    && errorMessage.contains("] not found.")) {
                errorMessage = errorMessage.replace("Document [", "Decoder [");
            }
            return new RestResponse(errorMessage, RestStatus.BAD_REQUEST.getStatus());
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
        if (payload.has("integration")) {
            return new RestResponse(
                    "Integration field is not allowed in PUT requests.", RestStatus.BAD_REQUEST.getStatus());
        }
        if (!payload.has(FIELD_RESOURCE) || !payload.get(FIELD_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
        String resourceId = this.toResourceId(decoderId);
        if (resourceNode.hasNonNull(FIELD_ID)) {
            String payloadId = resourceNode.get(FIELD_ID).asText();
            if (!payloadId.equals(resourceId) && !payloadId.equals(decoderId)) {
                return new RestResponse(
                        "Decoder ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }

    /** Updates the decoder document in the index. */
    private void updateDecoder(String decoderId, ObjectNode resourceNode) throws IOException {

        // Check if decoder exists before updating
        if (!this.decoderIndex.exists(decoderId)) {
            throw new IOException("Decoder [" + decoderId + "] not found.");
        }

        this.decoderIndex.create(decoderId, this.buildDecoderPayload(resourceNode));
    }

    /** Builds the decoder payload with document and space information. */
    private JsonNode buildDecoderPayload(ObjectNode resourceNode) {
        ObjectNode node = this.mapper.createObjectNode();
        node.put(FIELD_TYPE, DECODER_TYPE);
        node.set(KEY_DOCUMENT, resourceNode);
        // Add draft space
        ObjectNode spaceNode = this.mapper.createObjectNode();
        spaceNode.put(Constants.KEY_NAME, Space.DRAFT.toString());
        node.set(Constants.KEY_SPACE, spaceNode);

        return node;
    }

    /** Ensures the decoder index exists, creating it if necessary. */
    private void ensureIndexExists(Client client) throws IOException {
        if (!IndexHelper.indexExists(client, INDEX_DECODERS)) {
            try {
                this.decoderIndex.createIndex();
            } catch (Exception e) {
                throw new IOException("Failed to create index " + INDEX_DECODERS, e);
            }
        }
    }

    /** Converts an index document ID to a resource ID by removing the prefix. */
    private String toResourceId(String indexId) {
        if (indexId != null && indexId.startsWith(INDEX_ID_PREFIX)) {
            return indexId.substring(INDEX_ID_PREFIX.length());
        }
        return indexId;
    }

    /**
     * Sets the decoder index for testing purposes.
     *
     * @param decoderIndex the ContentIndex to use for decoder operations
     */
    public void setDecoderIndex(ContentIndex decoderIndex) {
        this.decoderIndex = decoderIndex;
    }

    /**
     * Preserves the date field from existing metadata and updates the modified timestamp.
     *
     * <p>For decoders, timestamps are stored at {@code metadata.author.date} and {@code
     * metadata.author.modified}. The date field is preserved from the existing document, while
     * modified is always updated to the current time.
     *
     * @param documentId the document ID to retrieve from the index
     * @param resourceNode the resource node to update with preserved metadata
     * @throws IOException if an error occurs retrieving the existing document
     */
    private void preserveMetadataAndUpdateTimestamp(String documentId, ObjectNode resourceNode)
            throws IOException {
        JsonNode existingDocument = this.decoderIndex.getDocument(documentId);
        if (existingDocument == null) {
            throw new IOException("Document [" + documentId + "] not found.");
        }

        JsonNode existingMetadata = null;
        String preservedDate = null;
        if (existingDocument.has(KEY_DOCUMENT) && existingDocument.get(KEY_DOCUMENT).isObject()) {
            JsonNode existingDoc = existingDocument.get(KEY_DOCUMENT);
            if (existingDoc.has(FIELD_METADATA) && existingDoc.get(FIELD_METADATA).isObject()) {
                existingMetadata = existingDoc.get(FIELD_METADATA);
                // For decoders, date is inside author node
                if (existingMetadata.has(FIELD_AUTHOR)
                        && existingMetadata.get(FIELD_AUTHOR).isObject()
                        && existingMetadata.get(FIELD_AUTHOR).has(FIELD_DATE)) {
                    preservedDate = existingMetadata.get(FIELD_AUTHOR).get(FIELD_DATE).asText();
                }
            }
        }

        ObjectNode requestMetadata = null;
        if (resourceNode.has(FIELD_METADATA) && resourceNode.get(FIELD_METADATA).isObject()) {
            requestMetadata = (ObjectNode) resourceNode.get(FIELD_METADATA);
        }

        ObjectNode finalMetadata;
        if (requestMetadata != null) {
            finalMetadata =
                    (ObjectNode) this.mapper.readTree(this.mapper.writeValueAsString(requestMetadata));
        } else if (existingMetadata != null) {
            finalMetadata =
                    (ObjectNode) this.mapper.readTree(this.mapper.writeValueAsString(existingMetadata));
        } else {
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

        // Set timestamps inside author node (Decoder format)
        if (preservedDate != null) {
            authorNode.put(FIELD_DATE, preservedDate);
        }
        authorNode.put(FIELD_MODIFIED, Instant.now().toString());

        resourceNode.set(FIELD_METADATA, finalMetadata);
    }
}
