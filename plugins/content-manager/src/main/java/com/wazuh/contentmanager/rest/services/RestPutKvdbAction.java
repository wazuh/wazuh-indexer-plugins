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
import org.opensearch.core.rest.RestStatus;
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
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.PUT;

public class RestPutKvdbAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutKvdbAction.class);
    private static final String ENDPOINT_NAME = "content_manager_kvdb_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_update";
    private static final String INTEGRATION_INDEX = ".cti-integrations";
    private static final String KVDB_INDEX = ".cti-kvdbs";
    private static final String KVDB_TYPE = "kvdb";
    private static final String FIELD_RESOURCE = "resource";
    private static final String FIELD_ID = "id";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_SPACE = "space";
    private static final String FIELD_NAME = "name";
    private static final String FIELD_INTEGRATION = "integration";
    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();

    public RestPutKvdbAction(EngineService engine) {
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
                        .path(PluginSettings.KVDBS_URI + "/{id}")
                        .method(PUT)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        request.param("id");
        return channel ->
                channel.sendResponse(this.handleRequest(request, client).toBytesRestResponse());
    }

    public RestResponse handleRequest(RestRequest request, Client client) {
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
            String integrationId = payload.get(FIELD_INTEGRATION).asText();
            validationError = this.validatePayload(payload, kvdbId);
            if (validationError != null) {
                return validationError;
            }

            ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
            // Use ID directly without prefix
            resourceNode.put(FIELD_ID, kvdbId);

            RestResponse engineResponse = this.validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }

            RestResponse validationResponse = this.validateIntegrationSpace(client, integrationId);
            if (validationResponse != null) {
                return validationResponse;
            }

            GetResponse getResponse = client.prepareGet(KVDB_INDEX, kvdbId).get();
            if (!getResponse.isExists() || getResponse.getSourceAsMap() == null) {
                return new RestResponse(
                        "KVDB [" + kvdbId + "] not found.", RestStatus.BAD_REQUEST.getStatus());
            }

            if (getResponse.getSourceAsMap().get(FIELD_SPACE) == null
                    || !(getResponse.getSourceAsMap().get(FIELD_SPACE) instanceof Map)
                    || !Space.DRAFT.equals(
                            String.valueOf(
                                    ((Map<?, ?>) getResponse.getSourceAsMap().get(FIELD_SPACE)).get(FIELD_NAME)))) {
                return new RestResponse(
                        "KVDBs can only be updated in draft space.", RestStatus.BAD_REQUEST.getStatus());
            }

            this.updateKvdb(client, kvdbId, resourceNode);

            return new RestResponse(
                    "KVDB updated successfully with ID: " + kvdbId, RestStatus.OK.getStatus());

        } catch (IOException e) {
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (OpenSearchParseException e) {
            log.error("Error updating KVDB: {}", e.getMessage(), e);
            return new RestResponse(
                    e.getMessage() != null ? e.getMessage() : "An unexpected error occurred.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

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

    private RestResponse validatePayload(JsonNode payload, String kvdbId) {
        if (!payload.has(FIELD_RESOURCE) || !payload.get(FIELD_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
        if (resourceNode.hasNonNull(FIELD_ID)) {
            String payloadId = resourceNode.get(FIELD_ID).asText();
            if (!payloadId.equals(kvdbId)) {
                return new RestResponse(
                        "KVDB ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }

    private RestResponse validateWithEngine(ObjectNode resourceNode) {
        ObjectNode enginePayload = this.mapper.createObjectNode();
        enginePayload.put(FIELD_TYPE, KVDB_TYPE);
        enginePayload.set(FIELD_RESOURCE, resourceNode);

        RestResponse response = this.engine.validate(enginePayload);
        if (response == null) {
            return new RestResponse(
                    "Invalid KVDB body, engine validation failed.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    private void updateKvdb(Client client, String kvdbId, ObjectNode resourceNode)
            throws IOException {

        ensureIndexExists(client);
        ContentIndex kvdbIndex = new ContentIndex(client, KVDB_INDEX, null);

        if (!kvdbIndex.exists(kvdbId)) {
            throw new IOException("KVDB [" + kvdbId + "] not found.");
        }

        kvdbIndex.create(kvdbId, this.buildKvdbPayload(resourceNode));
    }

    private JsonNode buildKvdbPayload(ObjectNode resourceNode) {
        ObjectNode node = this.mapper.createObjectNode();
        node.put(FIELD_TYPE, KVDB_TYPE);
        node.set(FIELD_DOCUMENT, resourceNode);
        ObjectNode spaceNode = this.mapper.createObjectNode();
        spaceNode.put(FIELD_NAME, Space.DRAFT.toString());
        node.set(FIELD_SPACE, spaceNode);

        return node;
    }

    private static void ensureIndexExists(Client client) throws IOException {
        if (!IndexHelper.indexExists(client, RestPutKvdbAction.KVDB_INDEX)) {
            ContentIndex index = new ContentIndex(client, RestPutKvdbAction.KVDB_INDEX, null);
            try {
                index.createIndex();
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                throw new IOException("Failed to create index " + RestPutKvdbAction.KVDB_INDEX, e);
            }
        }
    }

    private RestResponse validateIntegrationSpace(Client client, String integrationId) {
        GetResponse integrationResponse = client.prepareGet(INTEGRATION_INDEX, integrationId).get();

        if (!integrationResponse.isExists()) {
            return new RestResponse(
                    "Integration [" + integrationId + "] not found.", RestStatus.BAD_REQUEST.getStatus());
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(FIELD_SPACE)) {
            return new RestResponse(
                    "Integration [" + integrationId + "] does not have space information.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        Object spaceObj = source.get(FIELD_SPACE);
        if (!(spaceObj instanceof Map)) {
            return new RestResponse(
                    "Integration [" + integrationId + "] has invalid space information.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(FIELD_NAME);

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
