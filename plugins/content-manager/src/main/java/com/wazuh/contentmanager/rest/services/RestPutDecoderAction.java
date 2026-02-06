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
    // TODO: Move to a common constants class
    private static final String ENDPOINT_NAME = "content_manager_decoder_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_update";
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
     * Sets the decoder index for testing purposes.
     *
     * @param decoderIndex the ContentIndex to use for decoder operations
     */
    public void setDecoderIndex(ContentIndex decoderIndex) {
        this.decoderIndex = decoderIndex;
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
        this.decoderIndex = new ContentIndex(client, Constants.INDEX_DECODERS, null);
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
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_DECODERS, decoderId, "Decoder");
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus());
            }

            // Update the modified timestamp
            this.updateMetadata(decoderId, resourceNode);

            // Validate decoder with Wazuh Engine
            ObjectNode enginePayload = this.mapper.createObjectNode();
            enginePayload.set("resource", resourceNode);
            enginePayload.put("type", "decoder");
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
        String decoderId = request.param("id");
        if (decoderId == null || decoderId.isBlank()) {
            decoderId = request.param("decoder_id");
        }
        return decoderId;
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

        this.ensureIndexExists(client);

        // Check if decoder exists before updating
        if (!this.decoderIndex.exists(decoderId)) {
            throw new IOException("Decoder [" + decoderId + "] not found.");
        }

        this.decoderIndex.create(decoderId, this.buildDecoderPayload(resourceNode));
    }

    /** Builds the decoder payload with document and space information. */
    private JsonNode buildDecoderPayload(ObjectNode resourceNode) {
        ObjectNode node = this.mapper.createObjectNode();
        node.set(Constants.KEY_DOCUMENT, resourceNode);
        // Add draft space
        ObjectNode spaceNode = this.mapper.createObjectNode();
        spaceNode.put(Constants.KEY_NAME, Space.DRAFT.toString());
        node.set(Constants.KEY_SPACE, spaceNode);

        return node;
    }

    /** Ensures the decoder index exists, creating it if necessary. */
    private void ensureIndexExists(Client client) throws IOException {
        if (!IndexHelper.indexExists(client, Constants.INDEX_DECODERS)) {
            try {
                this.decoderIndex.createIndex();
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

        this.log.debug("Regenerated space hash for space={}", spaceName);
    }

    /**
     * Updates the metadata of the decoder and preserves date field.
     *
     * <p>For decoders, timestamps are stored at {@code metadata.author.date} and {@code
     * metadata.author.modified}. The date field is preserved from the existing document, while
     * modified is always updated to the current time.
     *
     * @param documentId the document ID to retrieve from the index
     * @param resourceNode the resource node to update with preserved metadata
     * @throws IOException if an error occurs retrieving the existing document
     */
    private void updateMetadata(String documentId, ObjectNode resourceNode) throws IOException {
        JsonNode existingDocument = this.decoderIndex.getDocument(documentId);
        if (existingDocument == null) {
            throw new IOException("Document [" + documentId + "] not found.");
        }

        JsonNode existingMetadata = null;
        String preservedDate = null;
        if (existingDocument.has(Constants.KEY_DOCUMENT)
                && existingDocument.get(Constants.KEY_DOCUMENT).isObject()) {
            JsonNode existingDoc = existingDocument.get(Constants.KEY_DOCUMENT);
            if (existingDoc.has(Constants.KEY_METADATA)
                    && existingDoc.get(Constants.KEY_METADATA).isObject()) {
                existingMetadata = existingDoc.get(Constants.KEY_METADATA);
                // For decoders, date is inside author node
                if (existingMetadata.has(Constants.KEY_AUTHOR)
                        && existingMetadata.get(Constants.KEY_AUTHOR).isObject()
                        && existingMetadata.get(Constants.KEY_AUTHOR).has(Constants.KEY_DATE)) {
                    preservedDate =
                            existingMetadata.get(Constants.KEY_AUTHOR).get(Constants.KEY_DATE).asText();
                }
            }
        }

        ObjectNode requestMetadata = null;
        if (resourceNode.has(Constants.KEY_METADATA)
                && resourceNode.get(Constants.KEY_METADATA).isObject()) {
            requestMetadata = (ObjectNode) resourceNode.get(Constants.KEY_METADATA);
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
        if (finalMetadata.has(Constants.KEY_AUTHOR)
                && finalMetadata.get(Constants.KEY_AUTHOR).isObject()) {
            authorNode = (ObjectNode) finalMetadata.get(Constants.KEY_AUTHOR);
        } else {
            authorNode = this.mapper.createObjectNode();
            finalMetadata.set(Constants.KEY_AUTHOR, authorNode);
        }

        // Set timestamps inside author node (Decoder format)
        if (preservedDate != null) {
            authorNode.put(Constants.KEY_DATE, preservedDate);
        }
        authorNode.put(Constants.KEY_MODIFIED, Instant.now().toString());

        resourceNode.set(Constants.KEY_METADATA, finalMetadata);
    }
}
