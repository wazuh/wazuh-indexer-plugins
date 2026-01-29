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
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for creating decoder resources.
 *
 * <p>Endpoint: POST /_plugins/_content_manager/decoders
 *
 * <p>Creates a decoder in the draft space and associates it with an integration.
 *
 * <p>HTTP responses:
 *
 * <ul>
 *   <li>202 Accepted: Decoder created successfully
 *   <li>400 Bad Request: Invalid payload or validation error
 *   <li>500 Internal Server Error: Engine unavailable or unexpected error
 * </ul>
 */
public class RestPostDecoderAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostDecoderAction.class);

    // TODO: Move to a common constants class
    private static final String ENDPOINT_NAME = "content_manager_decoder_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_create";
    private static final String DECODER_INDEX = ".cti-decoders";
    private static final String INTEGRATION_INDEX = ".cti-integrations";
    private static final String INDEX_ID_PREFIX = "d_";
    private static final String FIELD_INTEGRATION = "integration";
    private static final String FIELD_RESOURCE = "resource";
    private static final String FIELD_ID = "id";
    private static final String FIELD_DECODERS = "decoders";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_SPACE = "space";
    private static final String FIELD_NAME = "name";
    private static final String DECODER_TYPE = "decoder";

    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Constructs a new RestPostDecoderAction handler.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPostDecoderAction(EngineService engine) {
        this.engine = engine;
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.DECODERS_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        RestResponse response = this.handleRequest(request, client);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    /**
     * Handles the decoder creation request.
     *
     * @param request incoming REST request containing decoder payload
     * @param client the node client for index operations
     * @return a RestResponse describing the outcome
     */
    public RestResponse handleRequest(RestRequest request, Client client) {
        // Validate prerequisites
        RestResponse validationError = this.validatePrerequisites(request);
        if (validationError != null) {
            return validationError;
        }

        try {
            JsonNode payload = this.mapper.readTree(request.content().streamInput());
            // Validate payload structure
            validationError = this.validatePayload(payload);
            if (validationError != null) {
                return validationError;
            }
            ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
            String integrationId = payload.get(FIELD_INTEGRATION).asText();

            // Generate UUID and validate with engine
            resourceNode.put(FIELD_ID, UUID.randomUUID().toString());
            RestResponse engineResponse = this.validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }
            // Create decoder and update integration
            String decoderIndexId = toIndexId(resourceNode.get(FIELD_ID).asText());
            this.createDecoder(client, decoderIndexId, resourceNode);
            this.updateIntegrationWithDecoder(client, integrationId, decoderIndexId);

            return new RestResponse(
                    "Decoder created successfully with ID: " + decoderIndexId,
                    RestStatus.CREATED.getStatus());

        } catch (IOException e) {
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            log.error("Error creating decoder: {}", e.getMessage(), e);
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

    /** Validates the payload structure and required fields. */
    private RestResponse validatePayload(JsonNode payload) {
        if (!payload.has(FIELD_INTEGRATION) || payload.get(FIELD_INTEGRATION).asText("").isBlank()) {
            return new RestResponse("Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        if (!payload.has(FIELD_RESOURCE) || !payload.get(FIELD_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        if (payload.get(FIELD_RESOURCE).hasNonNull(FIELD_ID)) {
            return new RestResponse(
                    "Resource ID must not be provided on create.", RestStatus.BAD_REQUEST.getStatus());
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

    /** Creates the decoder document in the index. */
    private void createDecoder(Client client, String decoderIndexId, ObjectNode resourceNode)
            throws IOException {
        ContentIndex decoderIndex = new ContentIndex(client, DECODER_INDEX, null);
        decoderIndex.create(decoderIndexId, this.buildDecoderPayload(resourceNode));
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

    /** Converts a resource ID to an index document ID. */
    private static String toIndexId(String resourceId) {
        return INDEX_ID_PREFIX + resourceId;
    }

    /** Updates the integration document to include the new decoder reference. */
    @SuppressWarnings("unchecked")
    private void updateIntegrationWithDecoder(
            Client client, String integrationId, String decoderIndexId) throws IOException {
        GetResponse integrationResponse = client.prepareGet(INTEGRATION_INDEX, integrationId).get();

        if (!integrationResponse.isExists()) {
            throw new IOException(
                    "Integration ["
                            + integrationId
                            + "] not found when creating decoder ["
                            + decoderIndexId
                            + "].");
        }

        Map<String, Object> source = new HashMap<>(integrationResponse.getSourceAsMap());
        Map<String, Object> document = (Map<String, Object>) source.get(FIELD_DOCUMENT);
        List<String> decoders = this.extractDecodersList(document.get(FIELD_DECODERS));

        if (!decoders.contains(decoderIndexId)) {
            decoders.add(decoderIndexId);
        }

        document.put(FIELD_DECODERS, decoders);
        source.put(FIELD_DOCUMENT, document);

        client
                .index(
                        new IndexRequest(INTEGRATION_INDEX)
                                .id(integrationId)
                                .source(source)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }

    /** Extracts the decoders list from the document, handling type conversion. */
    private List<String> extractDecodersList(Object existing) {
        List<String> decoders = new ArrayList<>();
        if (existing instanceof List) {
            for (Object item : (List<?>) existing) {
                decoders.add(String.valueOf(item));
            }
        }
        return decoders;
    }
}
