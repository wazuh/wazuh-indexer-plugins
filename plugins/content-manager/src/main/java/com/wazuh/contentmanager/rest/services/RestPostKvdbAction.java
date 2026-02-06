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

import com.wazuh.contentmanager.utils.Constants;
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
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.POST;
import static com.wazuh.contentmanager.utils.Constants.INDEX_INTEGRATIONS;
import static com.wazuh.contentmanager.utils.Constants.INDEX_KVDBS;
import static com.wazuh.contentmanager.utils.Constants.KEY_NAME;
import static com.wazuh.contentmanager.utils.Constants.KEY_SPACE;

/**
 * REST handler for creating KVDB resources.
 *
 * <p>Endpoint: POST /_plugins/_content_manager/kvdbs
 *
 * <p>Creates a KVDB in the draft space and associates it with an integration.
 *
 * <p>HTTP responses:
 *
 * <ul>
 *   <li>202 Accepted: KVDB created successfully
 *   <li>400 Bad Request: Invalid payload or validation error
 *   <li>500 Internal Server Error: Engine unavailable or unexpected error
 * </ul>
 */
public class RestPostKvdbAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostKvdbAction.class);

    private static final String ENDPOINT_NAME = "content_manager_kvdb_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_create";

    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();
    private PolicyHashService policyHashService;

    /**
     * Constructs a new RestPostKvdbAction handler.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestPostKvdbAction(EngineService engine) {
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
                        .path(PluginSettings.KVDBS_URI)
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
     * Handles the KVDB creation request.
     *
     * @param request incoming REST request containing KVDB payload
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
            ObjectNode resourceNode = (ObjectNode) payload.get(Constants.KEY_RESOURCE);
            String integrationId = payload.get(Constants.KEY_INTEGRATION).asText();

            // Generate UUID
            String kvdbId = UUID.randomUUID().toString();
            resourceNode.put(Constants.KEY_ID, kvdbId);

            // Add timestamp metadata
            this.addMetadata(resourceNode);

            // Validate with engine
            RestResponse engineResponse = this.validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }

            // Validate that the Integration exists and is in draft space
            RestResponse validationResponse =
                    DocumentValidations.validateDocumentInSpaceWithResponse(
                            client, INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
            if (validationResponse != null) {
                return validationResponse;
            }

            // Create KVDB
            this.createKvdb(client, kvdbId, resourceNode);
            this.updateIntegrationWithKvdb(client, integrationId, kvdbId);

            // Regenerate space hash because space composition changed
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(
                    "KVDB created successfully with ID: " + kvdbId, RestStatus.CREATED.getStatus());

        } catch (IOException e) {
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            log.error("Error creating KVDB: {}", e.getMessage(), e);
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

    /** Creates the KVDB document in the index. */
    private void createKvdb(Client client, String kvdbIndexId, ObjectNode resourceNode)
            throws IOException {
        ContentIndex kvdbIndex = new ContentIndex(client, INDEX_KVDBS, null);
        kvdbIndex.create(kvdbIndexId, this.buildKvdbPayload(resourceNode));
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

    /** Updates the integration document to include the new KVDB reference. */
    @SuppressWarnings("unchecked")
    private void updateIntegrationWithKvdb(Client client, String integrationId, String kvdbIndexId)
            throws IOException {
        GetResponse integrationResponse = client.prepareGet(INDEX_INTEGRATIONS, integrationId).get();

        if (!integrationResponse.isExists()) {
            throw new IOException(
                    "Integration ["
                            + integrationId
                            + "] not found when creating KVDB ["
                            + kvdbIndexId
                            + "].");
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(Constants.KEY_DOCUMENT)) {
            throw new IOException(
                    "Can't find document in integration ["
                            + integrationId
                            + "] when creating KVDB ["
                            + kvdbIndexId
                            + "].");
        }
        Object documentObj = source.get(Constants.KEY_DOCUMENT);

        if (!(documentObj instanceof Map)) {
            throw new IOException(
                    "Integration document ["
                            + integrationId
                            + "] is invalid when creating KVDB ["
                            + kvdbIndexId
                            + "].");
        }

        Map<String, Object> document = new HashMap<>((Map<String, Object>) documentObj);
        List<String> kvdbs = this.extractKvdbsList(document.get(Constants.KEY_KVDBS));

        if (!kvdbs.contains(kvdbIndexId)) {
            kvdbs.add(kvdbIndexId);
        }

        document.put(Constants.KEY_KVDBS, kvdbs);
        source.put(Constants.KEY_DOCUMENT, document);

        // Regenerate integration hash and persist (complete operation)
        RestPostDecoderAction.regenerateIntegrationHash(client, integrationId, document, source);
        client
                .index(
                        new IndexRequest(INDEX_INTEGRATIONS)
                                .id(integrationId)
                                .source(source)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }

    /** Extracts the KVDBs list from the document, handling type conversion. */
    private List<String> extractKvdbsList(Object existing) {
        List<String> kvdbs = new ArrayList<>();
        if (existing instanceof List) {
            for (Object item : (List<?>) existing) {
                kvdbs.add(String.valueOf(item));
            }
        }
        return kvdbs;
    }

    /**
     * Adds metadata fields on the resource node
     *
     * @param resourceNode the resource node to update
     */
    private void addMetadata(ObjectNode resourceNode) {
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

        // Set timestamps
        metadataNode.put(Constants.KEY_DATE, currentTimestamp);
        metadataNode.put(Constants.KEY_MODIFIED, currentTimestamp);
    }

    /**
     * Validates that the integration exists and is in the draft space.
     *
     * @param client the OpenSearch client
     * @param integrationId the integration ID to validate
     * @return a RestResponse with error if validation fails, null otherwise
     */
    private RestResponse validateIntegrationSpace(Client client, String integrationId) {
        GetResponse integrationResponse = client.prepareGet(INDEX_INTEGRATIONS, integrationId).get();

        if (!integrationResponse.isExists()) {
            return new RestResponse(
                    "Integration [" + integrationId + "] not found.", RestStatus.BAD_REQUEST.getStatus());
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(KEY_SPACE)) {
            return new RestResponse(
                    "Integration [" + integrationId + "] does not have space information.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        Object spaceObj = source.get(KEY_SPACE);
        if (!(spaceObj instanceof Map)) {
            return new RestResponse(
                    "Integration [" + integrationId + "] has invalid space information.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(KEY_NAME);

        if (!Space.DRAFT.equals(String.valueOf(spaceName))) {
            return new RestResponse(
                    "Integration ["
                            + integrationId
                            + "] is not in draft space. Only integrations in draft space can have rules created.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        return null;
    }
}
