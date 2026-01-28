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
import org.opensearch.rest.BytesRestResponse;
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
import com.wazuh.contentmanager.cti.catalog.synchronizer.DecodersConsumerSynchronizer;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * TODO !CHANGE_ME POST /_plugins/content-manager/decoders
 *
 * <p>Creates a decoder in the local engine.
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestPostDecoderAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_decoder_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_create";
    private static final Logger log = LogManager.getLogger(RestPostDecoderAction.class);
    private static final String DECODER_MAPPINGS = "/mappings/cti-decoders-mappings.json";
    private static final String INTEGRATION_MAPPINGS = "/mappings/cti-integrations-mappings.json";
    private static final String DECODER_ALIAS = ".cti-decoders";
    private static final String INTEGRATION_ALIAS = ".cti-integration-decoders";
    private static final String DECODER_TYPE = "decoder";
    private static final String FIELD_INTEGRATION = "integration";
    private static final String FIELD_RESOURCE = "resource";
    private static final String FIELD_ID = "id";
    private static final String FIELD_DECODERS = "decoders";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_SPACE = "space";
    private static final String FIELD_NAME = "name";
    private final EngineService engine;

    /**
     * Constructs a new TODO !CHANGE_ME.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPostDecoderAction(EngineService engine) {
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
                        .path(PluginSettings.DECODERS_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request incoming request
     * @return a BytesRestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest(RestRequest request, Client client) {
        try {
            if (this.engine == null) {
                RestResponse error =
                        new RestResponse(
                                "Engine service unavailable.",
                                RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                return error.toBytesRestResponse();
            }

            if (!request.hasContent()) {
                RestResponse error =
                        new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
                return error.toBytesRestResponse();
            }

            ObjectMapper mapper = new ObjectMapper();
            JsonNode payload = mapper.readTree(request.content().streamInput());
            if (!payload.has(FIELD_INTEGRATION) || payload.get(FIELD_INTEGRATION).asText("").isBlank()) {
                RestResponse error =
                        new RestResponse(
                                "Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
                return error.toBytesRestResponse();
            }

            if (!payload.has(FIELD_RESOURCE) || !payload.get(FIELD_RESOURCE).isObject()) {
                RestResponse error =
                        new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
                return error.toBytesRestResponse();
            }

            ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
            if (resourceNode.hasNonNull(FIELD_ID)) {
                RestResponse error =
                        new RestResponse(
                                "Resource ID must not be provided on create.",
                                RestStatus.BAD_REQUEST.getStatus());
                return error.toBytesRestResponse();
            }

            // Generate UUID for the resource on creation
            resourceNode.put(FIELD_ID, UUID.randomUUID().toString());

            ObjectNode enginePayload = mapper.createObjectNode();
            enginePayload.put(FIELD_TYPE, DECODER_TYPE);
            enginePayload.set(FIELD_RESOURCE, resourceNode);
            RestResponse response = this.engine.validate(enginePayload);
            if (response == null) {
                RestResponse error =
                        new RestResponse(
                                "Engine returned an empty response.",
                                RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                return error.toBytesRestResponse();
            }

            if (client != null) {
                String decoderId = resourceNode.get(FIELD_ID).asText();
                String integrationId = payload.get(FIELD_INTEGRATION).asText();
                String decoderIndexName = getIndexName(DecodersConsumerSynchronizer.DECODER);
                ensureIndexExists(client, decoderIndexName, DECODER_MAPPINGS, DECODER_ALIAS);
                ContentIndex decoderIndex =
                        new ContentIndex(client, decoderIndexName, DECODER_MAPPINGS, DECODER_ALIAS);
                decoderIndex.create(decoderId, buildDecoderPayload(resourceNode));

                String integrationIndexName = getIndexName(DecodersConsumerSynchronizer.INTEGRATION);
                ensureIndexExists(
                        client, integrationIndexName, INTEGRATION_MAPPINGS, INTEGRATION_ALIAS);
                Map<String, Object> source =
                        IndexHelper.getDocumentSource(client, integrationIndexName, integrationId);
                if (source == null) {
                    log.warn(
                            "Integration [{}] not found when creating decoder [{}].",
                            integrationId,
                            decoderId);
                } else {
                    Object documentObj = source.get(FIELD_DOCUMENT);
                    if (!(documentObj instanceof Map)) {
                        log.warn(
                                "Integration document [{}] is invalid when creating decoder [{}].",
                                integrationId,
                                decoderId);
                    } else {
                        Map<String, Object> document = new HashMap<>();
                        for (Map.Entry<?, ?> entry : ((Map<?, ?>) documentObj).entrySet()) {
                            document.put(String.valueOf(entry.getKey()), entry.getValue());
                        }
                        Object existing = document.get(FIELD_DECODERS);
                        List<String> decoders = new ArrayList<>();
                        if (existing instanceof List) {
                            for (Object item : (List<?>) existing) {
                                decoders.add(String.valueOf(item));
                            }
                        }
                        if (!decoders.contains(decoderId)) {
                            decoders.add(decoderId);
                        }
                        document.put(FIELD_DECODERS, decoders);
                        source.put(FIELD_DOCUMENT, document);
                        ContentIndex integrationIndex =
                                new ContentIndex(
                                        client,
                                        integrationIndexName,
                                        INTEGRATION_MAPPINGS,
                                        INTEGRATION_ALIAS);
                        integrationIndex.create(integrationId, mapper.valueToTree(source));
                    }
                }

                PluginSettings settings = PluginSettings.getInstance();
                new PolicyHashService(client)
                        .calculateAndUpdate(
                                settings.getDecodersContext(), settings.getDecodersConsumer());
            }
            return response.toBytesRestResponse();
        } catch (IOException e) {
            RestResponse error =
                    new RestResponse("Invalid JSON content.", RestStatus.BAD_REQUEST.getStatus());
            return error.toBytesRestResponse();
        } catch (Exception e) {
            log.error("Error creating decoder: {}", e.getMessage(), e);
            RestResponse error =
                    new RestResponse(
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : "An unexpected error occurred while processing your request.",
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            return error.toBytesRestResponse();
        }
    }

    private static JsonNode buildDecoderPayload(ObjectNode resourceNode) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        node.put(FIELD_TYPE, DecodersConsumerSynchronizer.DECODER);
        node.set(FIELD_DOCUMENT, resourceNode);
        ObjectNode spaceNode = mapper.createObjectNode();
        spaceNode.put(FIELD_NAME, Space.DRAFT.toString());
        node.set(FIELD_SPACE, spaceNode);
        return node;
    }

    private static String getIndexName(String type) {
        PluginSettings settings = PluginSettings.getInstance();
        return String.format(
                java.util.Locale.ROOT,
                ".%s-%s-%s",
                settings.getDecodersContext(),
                settings.getDecodersConsumer(),
                type);
    }

    private static void ensureIndexExists(
            Client client, String indexName, String mappingsPath, String alias)
            throws IOException {
        if (!IndexHelper.indexExists(client, indexName)) {
            ContentIndex index = new ContentIndex(client, indexName, mappingsPath, alias);
            try {
                index.createIndex();
            } catch (Exception e) {
                throw new IOException("Failed to create index " + indexName, e);
            }
        }
    }
}
