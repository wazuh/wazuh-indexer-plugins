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
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.helpers.IntegrationHelper;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;
import static com.wazuh.contentmanager.utils.ContentManagerConstants.*;

/**d
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
        RestResponse response = this.handleRequest(request, client);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
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
        RestResponse validationError = IntegrationHelper.validatePrerequisites(this.engine, request);
        if (validationError != null) {
            return validationError;
        }

        try {
            JsonNode payload = mapper.readTree(request.content().streamInput());
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

            RestResponse engineResponse = IntegrationHelper.validateWithEngine(this.engine, resourceNode, KVDB_TYPE);
            if (engineResponse != null) {
                return engineResponse;
            }
            // Create KVDB and update integration
            String kvdbIndexId = resourceNode.get(FIELD_ID).asText();
            createKvdb(client, kvdbIndexId, resourceNode);
            IntegrationHelper.addResourceToIntegration(
                client, integrationId, kvdbIndexId, FIELD_KVDBS, KVDB_TYPE
            );

            return new RestResponse(
                "KVDB created successfully with ID: " + kvdbIndexId,
                RestStatus.CREATED.getStatus());

        } catch (IOException e) {
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            log.error("Error creating KVDB: {}", e.getMessage(), e);
            return new RestResponse(
                e.getMessage() != null ? e.getMessage() : "An unexpected error occurred.",
                RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /** Creates the KVDB document in the index. */
    private void createKvdb(Client client, String kvdbIndexId, ObjectNode resourceNode)
        throws IOException {
        ContentIndex kvdbIndex = new ContentIndex(client, KVDB_INDEX, null);
        kvdbIndex.create(kvdbIndexId, buildKvdbPayload(resourceNode));
    }

    /** Builds the KVDB payload with document and space information. */
    private JsonNode buildKvdbPayload(ObjectNode resourceNode) {
        ObjectNode node = mapper.createObjectNode();
        node.put(FIELD_TYPE, KVDB_TYPE);
        node.set(FIELD_DOCUMENT, resourceNode);
        // Add draft space
        ObjectNode spaceNode = mapper.createObjectNode();
        spaceNode.put(FIELD_NAME, Space.DRAFT.toString());
        node.set(FIELD_SPACE, spaceNode);
        return node;
    }
}
