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
import java.time.Instant;
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

public class RestPostKvdbAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostKvdbAction.class);

    private static final String ENDPOINT_NAME = "content_manager_kvdb_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_create";
    private static final String KVDB_INDEX = ".cti-kvdbs";
    private static final String INTEGRATION_INDEX = ".cti-integrations";
    private static final String FIELD_INTEGRATION = "integration";
    private static final String FIELD_RESOURCE = "resource";
    private static final String FIELD_ID = "id";
    private static final String FIELD_KVDBS = "kvdbs";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_TYPE = "type";
    private static final String FIELD_SPACE = "space";
    private static final String FIELD_NAME = "name";
    private static final String KVDB_TYPE = "kvdb";
    private static final String FIELD_METADATA = "metadata";
    private static final String FIELD_AUTHOR = "author";
    private static final String FIELD_DATE = "date";
    private static final String FIELD_MODIFIED = "modified";

    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();

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
        RestResponse response = this.handleRequest(request, client);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    public RestResponse handleRequest(RestRequest request, Client client) {
        RestResponse validationError = this.validatePrerequisites(request);
        if (validationError != null) {
            return validationError;
        }

        try {
            JsonNode payload = this.mapper.readTree(request.content().streamInput());
            validationError = this.validatePayload(payload);
            if (validationError != null) {
                return validationError;
            }
            ObjectNode resourceNode = (ObjectNode) payload.get(FIELD_RESOURCE);
            String integrationId = payload.get(FIELD_INTEGRATION).asText();

            String kvdbId = UUID.randomUUID().toString();
            resourceNode.put(FIELD_ID, kvdbId);

            this.addTimestampMetadata(resourceNode);

            RestResponse engineResponse = this.validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }

            RestResponse validationResponse = this.validateIntegrationSpace(client, integrationId);
            if (validationResponse != null) {
                return validationResponse;
            }

            // Create KVDB using raw UUID
            this.createKvdb(client, kvdbId, resourceNode);
            this.updateIntegrationWithKvdb(client, integrationId, kvdbId);

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

    private void createKvdb(Client client, String kvdbIndexId, ObjectNode resourceNode)
            throws IOException {
        ContentIndex kvdbIndex = new ContentIndex(client, KVDB_INDEX, null);
        kvdbIndex.create(kvdbIndexId, this.buildKvdbPayload(resourceNode));
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

    @SuppressWarnings("unchecked")
    private void updateIntegrationWithKvdb(Client client, String integrationId, String kvdbIndexId)
            throws IOException {
        GetResponse integrationResponse = client.prepareGet(INTEGRATION_INDEX, integrationId).get();

        if (!integrationResponse.isExists()) {
            throw new IOException(
                    "Integration ["
                            + integrationId
                            + "] not found when creating KVDB ["
                            + kvdbIndexId
                            + "].");
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(FIELD_DOCUMENT)) {
            throw new IOException(
                    "Can't find document in integration ["
                            + integrationId
                            + "] when creating KVDB ["
                            + kvdbIndexId
                            + "].");
        }
        Object documentObj = source.get(FIELD_DOCUMENT);

        if (!(documentObj instanceof Map)) {
            throw new IOException(
                    "Integration document ["
                            + integrationId
                            + "] is invalid when creating KVDB ["
                            + kvdbIndexId
                            + "].");
        }

        Map<String, Object> document = new HashMap<>((Map<String, Object>) documentObj);
        List<String> kvdbs = this.extractKvdbsList(document.get(FIELD_KVDBS));

        if (!kvdbs.contains(kvdbIndexId)) {
            kvdbs.add(kvdbIndexId);
        }

        document.put(FIELD_KVDBS, kvdbs);
        source.put(FIELD_DOCUMENT, document);

        client
                .index(
                        new IndexRequest(INTEGRATION_INDEX)
                                .id(integrationId)
                                .source(source)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }

    private List<String> extractKvdbsList(Object existing) {
        List<String> kvdbs = new ArrayList<>();
        if (existing instanceof List) {
            for (Object item : (List<?>) existing) {
                kvdbs.add(String.valueOf(item));
            }
        }
        return kvdbs;
    }

    private void addTimestampMetadata(ObjectNode resourceNode) {
        String currentTimestamp = Instant.now().toString();

        ObjectNode metadataNode;
        if (resourceNode.has(FIELD_METADATA) && resourceNode.get(FIELD_METADATA).isObject()) {
            metadataNode = (ObjectNode) resourceNode.get(FIELD_METADATA);
        } else {
            metadataNode = this.mapper.createObjectNode();
            resourceNode.set(FIELD_METADATA, metadataNode);
        }

        ObjectNode authorNode;
        if (metadataNode.has(FIELD_AUTHOR) && metadataNode.get(FIELD_AUTHOR).isObject()) {
            authorNode = (ObjectNode) metadataNode.get(FIELD_AUTHOR);
        } else {
            authorNode = this.mapper.createObjectNode();
            metadataNode.set(FIELD_AUTHOR, authorNode);
        }

        authorNode.put(FIELD_DATE, currentTimestamp);
        authorNode.put(FIELD_MODIFIED, currentTimestamp);
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
