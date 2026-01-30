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

import com.google.gson.JsonObject;
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
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.helpers.IntegrationHelper;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;
import static com.wazuh.contentmanager.utils.ContentManagerConstants.*;

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

    private static final String ENDPOINT_NAME = "content_manager_decoder_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_create";

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
        RestResponse validationError = IntegrationHelper.validatePrerequisites(this.engine, request);
        if (validationError != null) {
            return validationError;
        }

        try {
            JsonNode payload = this.mapper.readTree(request.content().streamInput());
            // Validate payload structure
            validationError = IntegrationHelper.validatePayload(payload);
            if (validationError != null) {
                return validationError;
            }
            ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
            String integrationId = payload.get(FIELD_INTEGRATION).asText();

            // Validate integration is in draft space
            RestResponse spaceValidation = IntegrationHelper.validateIntegrationSpace(client, integrationId);
            if (spaceValidation != null) {
                return spaceValidation;
            }

            // Generate UUID and validate with engine
            resourceNode.put(FIELD_ID, INDEX_ID_PREFIX + UUID.randomUUID().toString());

            // Add timestamp metadata
            IntegrationHelper.addTimestampMetadata(this.mapper, resourceNode, true, null);

            RestResponse engineResponse = IntegrationHelper.validateWithEngine(this.engine, resourceNode, DECODER_TYPE);
            if (engineResponse != null) {
                return engineResponse;
            }
            // Create decoder and update integration
            String decoderIndexId = resourceNode.get(FIELD_ID).asText();
            this.createDecoder(client, decoderIndexId, resourceNode);
            IntegrationHelper.addResourceToIntegration(
                client, integrationId, decoderIndexId, FIELD_DECODERS, DECODER_TYPE
            );

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

    /** Creates the decoder document in the index. */
    private void createDecoder(Client client, String decoderIndexId, ObjectNode resourceNode)
            throws IOException {
        ContentIndex decoderIndex = new ContentIndex(client, DECODER_INDEX, null);
        decoderIndex.create(decoderIndexId, this.buildDecoderPayload(resourceNode));
    }

    /** Builds the decoder payload with document and space information. */
    private JsonObject buildDecoderPayload(ObjectNode resourceNode) {
        // Convert resourceNode (Jackson) to Gson JsonObject
        com.google.gson.JsonParser parser = new com.google.gson.JsonParser();
        com.google.gson.JsonObject document = parser.parse(resourceNode.toString()).getAsJsonObject();

        com.google.gson.JsonObject payload = new com.google.gson.JsonObject();
        payload.addProperty(FIELD_TYPE, DECODER_TYPE);
        payload.add(FIELD_DOCUMENT, document);
        com.google.gson.JsonObject spaceObject = new com.google.gson.JsonObject();
        spaceObject.addProperty(FIELD_NAME, Space.DRAFT.toString());
        payload.add(FIELD_SPACE, spaceObject);
        return payload;
    }

}
