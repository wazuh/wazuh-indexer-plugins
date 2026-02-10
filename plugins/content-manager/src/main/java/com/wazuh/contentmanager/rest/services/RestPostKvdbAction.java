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

            // Validate that the Integration exists and is in draft space
            String spaceError =
                    DocumentValidations.validateDocumentInSpace(
                            client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
            if (spaceError != null) {
                return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());
            }

            // Generate UUID
            String kvdbId = UUID.randomUUID().toString();
            resourceNode.put(Constants.KEY_ID, kvdbId);

            // Add timestamp metadata
            ContentUtils.updateTimestampMetadata(resourceNode, true);

            // Validate with engine
            RestResponse engineResponse = this.engine.validateResource(Constants.KEY_KVDB, resourceNode);
            if (engineResponse.getStatus() != RestStatus.OK.getStatus()) {
                log.error(Constants.E_LOG_ENGINE_VALIDATION, engineResponse.getMessage());
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Create KVDB in Index
            ContentIndex kvdbIndex = new ContentIndex(client, Constants.INDEX_KVDBS, null);
            kvdbIndex.create(
                    kvdbId,
                    ContentUtils.buildCtiWrapper(Constants.KEY_KVDB, resourceNode, Space.DRAFT.toString()));

            // Link to Integration
            ContentUtils.linkResourceToIntegration(client, integrationId, kvdbId, Constants.KEY_KVDBS);

            // Regenerate space hash
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(kvdbId, RestStatus.CREATED.getStatus());

        } catch (IOException e) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            log.error(
                    Constants.E_LOG_OPERATION_FAILED, "creating", Constants.KEY_KVDB, e.getMessage(), e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
