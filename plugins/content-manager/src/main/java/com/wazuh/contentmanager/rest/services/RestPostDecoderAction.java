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
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.DocumentValidations;

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

    private static final String ENDPOINT_NAME = "content_manager_decoder_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_create";

    private static final ObjectMapper mapper = new ObjectMapper();
    private final EngineService engine;
    private PolicyHashService policyHashService;

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
        this.policyHashService = new PolicyHashService(client);
        RestResponse response = this.handleRequest(request, client);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
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
            JsonNode payload = mapper.readTree(request.content().streamInput());
            // Validate payload structure
            validationError = this.validatePayload(payload);
            if (validationError != null) {
                return validationError;
            }
            ObjectNode resourceNode = (ObjectNode) payload.get(Constants.KEY_RESOURCE);
            String integrationId = payload.get(Constants.KEY_INTEGRATION).asText();

            // Validate integration is in draft space
            String spaceValidationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
            if (spaceValidationError != null) {
                return new RestResponse(spaceValidationError, RestStatus.BAD_REQUEST.getStatus());
            }

            // Generate UUID and validate with engine
            String decoderId = UUID.randomUUID().toString();
            resourceNode.put(Constants.KEY_ID, decoderId);

            // Add timestamp metadata
            this.addTimestampMetadata(resourceNode, true);

            // Validate integration with Wazuh Engine
            ObjectNode enginePayload = mapper.createObjectNode();
            enginePayload.set(Constants.KEY_RESOURCE, resourceNode);
            enginePayload.put(Constants.KEY_TYPE, Constants.KEY_DECODER);
            final RestResponse engineValidation = this.engine.validate(enginePayload);
            if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
                return new RestResponse(engineValidation.getMessage(), engineValidation.getStatus());
            }

            // Create decoder using raw UUID
            this.createDecoder(client, decoderId, resourceNode);
            this.updateIntegrationWithDecoder(client, integrationId, decoderId);

            // Regenerate space hash because space composition changed
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(
                    "Decoder created successfully with ID: " + decoderId, RestStatus.CREATED.getStatus());

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
        if (!payload.has(Constants.KEY_INTEGRATION) || payload.get(Constants.KEY_INTEGRATION).asText("").isBlank()) {
            return new RestResponse("Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        if (!payload.has(Constants.KEY_RESOURCE) || !payload.get(Constants.KEY_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        if (payload.get(Constants.KEY_RESOURCE).hasNonNull(Constants.KEY_ID)) {
            return new RestResponse(
                    "Resource ID must not be provided on create.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /** Creates the decoder document in the index. */
    private void createDecoder(Client client, String decoderIndexId, ObjectNode resourceNode)
            throws IOException {
        ContentIndex decoderIndex = new ContentIndex(client, Constants.INDEX_DECODERS, null);
        decoderIndex.create(decoderIndexId, this.buildDecoderPayload(resourceNode));
    }

    /** Builds the decoder payload with document and space information. */
    private JsonObject buildDecoderPayload(ObjectNode resourceNode) {
        // Convert resourceNode (Jackson) to Gson JsonObject
        com.google.gson.JsonParser parser = new com.google.gson.JsonParser();
        com.google.gson.JsonObject document = parser.parse(resourceNode.toString()).getAsJsonObject();

        com.google.gson.JsonObject payload = new com.google.gson.JsonObject();
        payload.addProperty(Constants.KEY_TYPE, Constants.KEY_DECODER);
        payload.add(Constants.KEY_DOCUMENT, document);
        com.google.gson.JsonObject spaceObject = new com.google.gson.JsonObject();
        spaceObject.addProperty(Constants.KEY_NAME, Space.DRAFT.toString());
        payload.add(Constants.KEY_SPACE, spaceObject);
        return payload;
    }

    /** Updates the integration document to include the new decoder reference. */
    @SuppressWarnings("unchecked")
    private void updateIntegrationWithDecoder(
            Client client, String integrationId, String decoderIndexId) throws IOException {
        GetResponse integrationResponse = client.prepareGet(Constants.INDEX_INTEGRATIONS, integrationId).get();

        if (!integrationResponse.isExists()) {
            throw new IOException(
                    "Integration ["
                            + integrationId
                            + "] not found when creating decoder ["
                            + decoderIndexId
                            + "].");
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(Constants.KEY_DOCUMENT)) {
            throw new IOException(
                    "Can't find document in integration ["
                            + integrationId
                            + "] when creating decoder ["
                            + decoderIndexId
                            + "].");
        }
        Object documentObj = source.get(Constants.KEY_DOCUMENT);

        if (!(documentObj instanceof Map)) {
            throw new IOException(
                    "Integration document ["
                            + integrationId
                            + "] is invalid when creating decoder ["
                            + decoderIndexId
                            + "].");
        }

        Object spaceObj = source.get(Constants.KEY_SPACE);
        if (!(spaceObj instanceof Map)) {
            throw new IOException("Integration [" + integrationId + "] has invalid space information.");
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(Constants.KEY_NAME);
        if (!Space.DRAFT.equals(String.valueOf(spaceName))) {
            throw new IOException(
                    "Integration ["
                            + integrationId
                            + "] is not in draft space. Only integrations in draft space can have rules created.");
        }

        Map<String, Object> document = new HashMap<>((Map<String, Object>) documentObj);
        List<String> decoders = this.extractDecodersList(document.get(Constants.KEY_DECODERS));

        if (!decoders.contains(decoderIndexId)) {
            decoders.add(decoderIndexId);
        }

        document.put(Constants.KEY_DECODERS, decoders);
        source.put(Constants.KEY_DOCUMENT, document);

        // Regenerate integration hash and persist
        regenerateIntegrationHash(client, integrationId, document, source);
        client
                .index(
                        new IndexRequest(Constants.INDEX_INTEGRATIONS)
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

    /**
     * Adds or updates timestamp metadata to the resource node.
     *
     * @param resourceNode the resource node to update
     * @param isCreate true if creating (sets both date and modified), false if updating (sets only
     *     modified)
     */
    private void addTimestampMetadata(ObjectNode resourceNode, boolean isCreate) {
        String currentTimestamp = Instant.now().toString();

        // Ensure metadata node exists
        ObjectNode metadataNode;
        if (resourceNode.has(Constants.KEY_METADATA) && resourceNode.get(Constants.KEY_METADATA).isObject()) {
            metadataNode = (ObjectNode) resourceNode.get(Constants.KEY_METADATA);
        } else {
            metadataNode = mapper.createObjectNode();
            resourceNode.set(Constants.KEY_METADATA, metadataNode);
        }

        // Ensure author node exists
        ObjectNode authorNode;
        if (metadataNode.has(Constants.KEY_AUTHOR) && metadataNode.get(Constants.KEY_AUTHOR).isObject()) {
            authorNode = (ObjectNode) metadataNode.get(Constants.KEY_AUTHOR);
        } else {
            authorNode = mapper.createObjectNode();
            metadataNode.set(Constants.KEY_AUTHOR, authorNode);
        }

        // Set timestamps
        if (isCreate) {
            authorNode.put(Constants.KEY_DATE, currentTimestamp);
        }
        authorNode.put(Constants.KEY_MODIFIED, currentTimestamp);
    }

    /**
     * Regenerates the integration hash after its document has changed and persists it. This is a
     * complete operation that updates the hash and saves to the index.
     *
     * @param client the OpenSearch client
     * @param integrationId the integration ID
     * @param document the updated document content
     * @param source the integration source map to update with the new hash
     * @throws IOException if persistence fails
     */
    static void regenerateIntegrationHash(
            Client client, String integrationId, Map<String, Object> document, Map<String, Object> source)
            throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode documentNode = mapper.valueToTree(document);
        String newIntegrationHash = HashCalculator.sha256(documentNode.toString());
        Map<String, Object> hashMap = new HashMap<>();
        hashMap.put("sha256", newIntegrationHash);
        source.put("hash", hashMap);

        log.debug(
                "Regenerated integration hash for id={} (hashPrefix={})",
                integrationId,
                newIntegrationHash.length() >= 12
                        ? newIntegrationHash.substring(0, 12)
                        : newIntegrationHash);

        // Persist the updated integration with new hash
        client
                .index(
                        new IndexRequest(Constants.INDEX_INTEGRATIONS)
                                .id(integrationId)
                                .source(source)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }

    /**
     * Validates that the integration exists and is in the draft space.
     *
     * @param client the OpenSearch client
     * @param integrationId the integration ID to validate
     * @return a RestResponse with error if validation fails, null otherwise
     */
    private RestResponse validateIntegrationSpace(Client client, String integrationId) {
        GetResponse integrationResponse = client.prepareGet(Constants.INDEX_INTEGRATIONS, integrationId).get();

        if (!integrationResponse.isExists()) {
            return new RestResponse(
                    "Integration [" + integrationId + "] not found.", RestStatus.BAD_REQUEST.getStatus());
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(Constants.KEY_SPACE)) {
            return new RestResponse(
                    "Integration [" + integrationId + "] does not have space information.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        Object spaceObj = source.get(Constants.KEY_SPACE);
        if (!(spaceObj instanceof Map)) {
            return new RestResponse(
                    "Integration [" + integrationId + "] has invalid space information.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(Constants.KEY_NAME);

        if (!Space.DRAFT.equals(String.valueOf(spaceName))) {
            return new RestResponse(
                    "Integration ["
                            + integrationId
                            + "] is not in draft space. Only integrations in draft space can have decoders created.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        return null;
    }
}
