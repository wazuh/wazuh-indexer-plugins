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
import org.opensearch.OpenSearchParseException;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.cti.catalog.utils.MetadataPreservationHelper;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.PUT;
import static com.wazuh.contentmanager.utils.Constants.INDEX_INTEGRATIONS;
import static com.wazuh.contentmanager.utils.Constants.INDEX_KVDBS;
import static com.wazuh.contentmanager.utils.Constants.KEY_DOCUMENT;
import static com.wazuh.contentmanager.utils.Constants.KEY_INTEGRATION;
import static com.wazuh.contentmanager.utils.Constants.KEY_KVDBS;
import static com.wazuh.contentmanager.utils.Constants.KEY_NAME;
import static com.wazuh.contentmanager.utils.Constants.KEY_RESOURCE;
import static com.wazuh.contentmanager.utils.Constants.KEY_SPACE;

/**
 * REST handler for updating CTI KVDBs.
 *
 * <p>Endpoint: PUT /_plugins/content-manager/kvdbs/{kvdb_id}
 *
 * <p>This handler processes KVDB update requests. The KVDB is validated against the Wazuh engine
 * before being stored in the index with DRAFT space.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: KVDB updated successfully after engine validation.
 *   <li>400 Bad Request: Missing or invalid request body, KVDB ID mismatch, or validation error.
 *   <li>500 Internal Server Error: Unexpected error during processing or engine unavailable.
 * </ul>
 */
public class RestPutKvdbAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutKvdbAction.class);
    // TODO: Move to a common constants class
    private static final String ENDPOINT_NAME = "content_manager_kvdb_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_update";
    private static final String INDEX_ID_PREFIX = "d_";
    private static final String KVDB_TYPE = "kvdb";
    private static final String FIELD_ID = "id";
    private static final String FIELD_TYPE = "type";
    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Constructs a new RestPutKvdbAction handler.
     *
     * @param engine the engine service instance for communication with the Wazuh engine
     */
    public RestPutKvdbAction(EngineService engine) {
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
                        .path(PluginSettings.KVDBS_URI + "/{id}")
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
     * Handles the KVDB update request.
     *
     * <p>This method validates the request payload, ensures the KVDB ID matches, validates the KVDB
     * with the Wazuh engine, and stores the updated KVDB in the index.
     *
     * @param request the incoming REST request containing the KVDB data to update
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
            String kvdbId = request.param("id");
            if (kvdbId == null || kvdbId.isBlank()) {
                return new RestResponse("KVDB ID is required.", RestStatus.BAD_REQUEST.getStatus());
            }

            JsonNode payload = this.mapper.readTree(request.content().streamInput());
            // Validate payload structure
            validationError = this.validatePayload(payload, kvdbId);
            if (validationError != null) {
                return validationError;
            }

            ObjectNode resourceNode = (ObjectNode) payload.get(KEY_RESOURCE);
            String resourceId = toResourceId(kvdbId);
            resourceNode.put(FIELD_ID, resourceId);

            ensureIndexExists(client);
            ContentIndex kvdbIndex = new ContentIndex(client, INDEX_KVDBS, null);
            MetadataPreservationHelper.preserveMetadataAndUpdateTimestamp(
                    this.mapper, kvdbIndex, kvdbId, resourceNode);

            // Validate with engine
            RestResponse engineResponse = this.validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }

            // Validate that the Integration exists and is in draft space
            RestResponse validationResponse;
            String integrationId = this.findIntegrationForKvdb(client, kvdbId);
            if (integrationId != null) {
                validationResponse = this.validateIntegrationSpace(client, integrationId);
                if (validationResponse != null) {
                    return validationResponse;
                }
            }

            // Validate KVDB exists and is in draft space
            validationResponse =
                    DocumentValidations.validateDocumentInSpaceWithResponse(
                            client, INDEX_KVDBS, kvdbId, "KVDB");
            if (validationResponse != null) {
                return validationResponse;
            }

            // Update KVDB
            this.updateKvdb(client, kvdbId, resourceNode);

            return new RestResponse(
                    "KVDB updated successfully with ID: " + kvdbId, RestStatus.OK.getStatus());

        } catch (IOException e) {
            String errorMessage = e.getMessage();
            if (errorMessage != null
                    && errorMessage.contains("Document [")
                    && errorMessage.contains("] not found.")) {
                errorMessage = errorMessage.replace("Document [", "KVDB [");
            }
            return new RestResponse(errorMessage, RestStatus.BAD_REQUEST.getStatus());
        } catch (OpenSearchParseException e) {
            log.error("Error updating KVDB: {}", e.getMessage(), e);
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
    private RestResponse validatePayload(JsonNode payload, String kvdbId) {
        if (payload.has(KEY_INTEGRATION)) {
            return new RestResponse(
                    "Integration field is not allowed in PUT requests.", RestStatus.BAD_REQUEST.getStatus());
        }
        if (!payload.has(KEY_RESOURCE) || !payload.get(KEY_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        ObjectNode resourceNode = (ObjectNode) payload.get(KEY_RESOURCE);
        String resourceId = toResourceId(kvdbId);
        if (resourceNode.hasNonNull(FIELD_ID)) {
            String payloadId = resourceNode.get(FIELD_ID).asText();
            if (!payloadId.equals(resourceId) && !payloadId.equals(kvdbId)) {
                return new RestResponse(
                        "KVDB ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }

    /** Validates the resource with the engine service. */
    private RestResponse validateWithEngine(ObjectNode resourceNode) {
        ObjectNode enginePayload = this.mapper.createObjectNode();
        enginePayload.put(FIELD_TYPE, KVDB_TYPE);
        enginePayload.set(KEY_RESOURCE, resourceNode);

        RestResponse response = this.engine.validate(enginePayload);
        if (response == null) {
            return new RestResponse(
                    "Invalid KVDB body, engine validation failed.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /** Updates the KVDB document in the index. */
    private void updateKvdb(Client client, String kvdbId, ObjectNode resourceNode)
            throws IOException {

        ensureIndexExists(client);
        ContentIndex kvdbIndex = new ContentIndex(client, INDEX_KVDBS, null);

        // Check if KVDB exists before updating
        if (!kvdbIndex.exists(kvdbId)) {
            throw new IOException("KVDB [" + kvdbId + "] not found.");
        }

        kvdbIndex.create(kvdbId, this.buildKvdbPayload(resourceNode));
    }

    /** Builds the KVDB payload with document and space information. */
    private JsonNode buildKvdbPayload(ObjectNode resourceNode) {
        ObjectNode node = this.mapper.createObjectNode();
        node.put(FIELD_TYPE, KVDB_TYPE);
        node.set(KEY_DOCUMENT, resourceNode);
        // Add draft space
        ObjectNode spaceNode = this.mapper.createObjectNode();
        spaceNode.put(KEY_NAME, Space.DRAFT.toString());
        node.set(KEY_SPACE, spaceNode);

        return node;
    }

    /** Ensures the KVDB index exists, creating it if necessary. */
    private static void ensureIndexExists(Client client) throws IOException {
        if (!IndexHelper.indexExists(client, INDEX_KVDBS)) {
            ContentIndex index = new ContentIndex(client, INDEX_KVDBS, null);
            try {
                index.createIndex();
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                throw new IOException("Failed to create index " + INDEX_KVDBS, e);
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
     * Finds the integration ID associated with a KVDB by searching for integrations that reference
     * it.
     *
     * @param client the OpenSearch client
     * @param kvdbId the KVDB ID to search for
     * @return the integration ID if found, null otherwise
     */
    private String findIntegrationForKvdb(Client client, String kvdbId) {
        try {
            SearchRequest searchRequest = new SearchRequest(INDEX_INTEGRATIONS);
            searchRequest.source().query(QueryBuilders.termQuery(KEY_DOCUMENT + "." + KEY_KVDBS, kvdbId));
            SearchResponse searchResponse = client.search(searchRequest).actionGet();
            if (searchResponse.getHits().getHits().length > 0) {
                return searchResponse.getHits().getHits()[0].getId();
            }
        } catch (Exception e) {
            log.warn("Error finding integration for KVDB [{}]: {}", kvdbId, e.getMessage());
        }
        return null;
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
                            + "] is not in draft space. KVDBs can only be updated when their associated integration is in draft space.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        return null;
    }
}
