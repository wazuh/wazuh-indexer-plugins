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
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.POST;

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
        RestResponse validationError = DocumentValidations.validatePrerequisites(this.engine, request);
        if (validationError != null) {
            return validationError;
        }

        try {
            JsonNode payload = this.mapper.readTree(request.content().streamInput());

            // Validate payload structure
            validationError = DocumentValidations.validateResourcePayload(payload, null, true);
            if (validationError != null) {
                return validationError;
            }
            ObjectNode resourceNode = (ObjectNode) payload.get(Constants.KEY_RESOURCE);
            String integrationId = payload.get(Constants.KEY_INTEGRATION).asText();

            // Generate UUID
            String kvdbId = UUID.randomUUID().toString();
            resourceNode.put(Constants.KEY_ID, kvdbId);

            // Add timestamp metadata
            ContentUtils.updateTimestampMetadata(resourceNode, true);

            // Validate with engine
            RestResponse engineResponse = this.validateWithEngine(resourceNode);
            if (engineResponse != null) {
                return engineResponse;
            }

            // Validate that the Integration exists and is in draft space
            RestResponse validationResponse =
                    DocumentValidations.validateDocumentInSpaceWithResponse(
                            client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
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
        try {
            ContentIndex kvdbIndex = new ContentIndex(client, Constants.INDEX_KVDBS, null);
            kvdbIndex.create(kvdbIndexId, this.buildKvdbPayload(resourceNode));
        } catch (Exception e) {
            throw new IOException(e);
        }
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
        GetResponse integrationResponse =
                client.prepareGet(Constants.INDEX_INTEGRATIONS, integrationId).get();

        if (!integrationResponse.isExists()) {
            throw new IOException("Integration [" + integrationId + "] not found.");
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(Constants.KEY_DOCUMENT)) {
            throw new IOException("Can't find document in integration [" + integrationId + "].");
        }
        Object documentObj = source.get(Constants.KEY_DOCUMENT);

        if (!(documentObj instanceof Map)) {
            throw new IOException("Integration document [" + integrationId + "] is invalid.");
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
}
