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
    private static final String ENDPOINT_NAME = "content_manager_decoder_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_update";
    private static final Logger log = LogManager.getLogger(RestPutDecoderAction.class);
    private static final String INDEX_ID_PREFIX = "d_";
    private static final String DECODER_MAPPINGS = "/mappings/cti-decoders-mappings.json";
    private static final String DECODER_ALIAS = ".cti-decoders";
    private static final String DECODER_INDEX = DECODER_ALIAS;
    private static final String DECODER_TYPE = "decoder";
    private static final String FIELD_RESOURCE = "resource";
    private static final String FIELD_ID = "id";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_SPACE = "space";
    private static final String FIELD_NAME = "name";
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
        return channel -> channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
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
        RestResponse validationError = validatePrerequisites(request);
        if (validationError != null) {
            return validationError;
        }

        try {
            String decoderId = extractDecoderId(request);
            if (decoderId == null || decoderId.isBlank()) {
                return new RestResponse("Decoder ID is required.", RestStatus.BAD_REQUEST.getStatus());
            }

            JsonNode payload = mapper.readTree(request.content().streamInput());
            // Validate payload structure
            validationError = validatePayload(payload, decoderId);
            if (validationError != null) {
                return validationError;
            }

            ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
            String resourceId = toResourceId(decoderId);
            resourceNode.put(FIELD_ID, resourceId);

            // Validate with engine
            RestResponse engineResponse = validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }

            // Update decoder
            updateDecoder(client, decoderId, resourceNode);

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
        String resourceId = toResourceId(decoderId);
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
        ObjectNode enginePayload = mapper.createObjectNode();
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
        if (client == null) {
            return;
        }

        ensureIndexExists(client, DECODER_INDEX, DECODER_MAPPINGS, DECODER_ALIAS);
        ContentIndex decoderIndex = new ContentIndex(client, DECODER_INDEX, null);

        // Check if decoder exists before updating
        if (!decoderIndex.exists(decoderId)) {
            throw new IOException("Decoder [" + decoderId + "] not found.");
        }

        decoderIndex.create(decoderId, buildDecoderPayload(resourceNode));
    }

    /** Builds the decoder payload with document and space information. */
    private JsonNode buildDecoderPayload(ObjectNode resourceNode) {
        ObjectNode node = mapper.createObjectNode();
        node.put(FIELD_TYPE, DECODER_TYPE);
        node.set(FIELD_DOCUMENT, resourceNode);
        // Add draft space
        ObjectNode spaceNode = mapper.createObjectNode();
        spaceNode.put(FIELD_NAME, Space.DRAFT.toString());
        node.set(FIELD_SPACE, spaceNode);

        return node;
    }

    /** Ensures the decoder index exists, creating it if necessary. */
    private static void ensureIndexExists(
            Client client, String indexName, String mappingsPath, String alias) throws IOException {
        if (!IndexHelper.indexExists(client, indexName)) {
            ContentIndex index = new ContentIndex(client, indexName, mappingsPath, alias);
            try {
                index.createIndex();
            } catch (Exception e) {
                throw new IOException("Failed to create index " + indexName, e);
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
}
