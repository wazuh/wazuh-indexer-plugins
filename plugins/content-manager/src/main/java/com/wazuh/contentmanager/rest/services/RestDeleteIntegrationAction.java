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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/content-manager/integrations/{id}
 *
 * <p>Deletes an existing integration from the draft space.
 *
 * <p>Possible HTTP responses: - 200 OK: Integration deleted successfully. - 400 Bad Request:
 * Integration is not in draft space or other validation error. - 404 Not Found: Integration with
 * specified ID was not found. - 500 Internal Server Error: Unexpected error during processing.
 */
public class RestDeleteIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_delete";

    private ContentIndex integrationsIndex;
    private PolicyHashService policyHashService;
    private SecurityAnalyticsService service;
    private final Logger log = LogManager.getLogger(RestDeleteIntegrationAction.class);
    private static final String CTI_DECODERS_INDEX = ".cti-decoders";
    private static final String CTI_INTEGRATIONS_INDEX = ".cti-integrations";
    private static final String CTI_KVDBS_INDEX = ".cti-kvdbs";
    private static final String CTI_POLICIES_INDEX = ".cti-policies";
    private static final String CTI_RULES_INDEX = ".cti-rules";
    private static final String DRAFT_SPACE_NAME = "draft";

    private NodeClient nodeClient;

    /**
     * Constructs a new RestDeleteIntegrationAction.
     *
     * <p>Note: The engine parameter is kept for API compatibility with other integration actions but
     * is not used for delete operations.
     *
     * @param engine The engine service (unused in delete operations).
     */
    @SuppressWarnings("unused")
    public RestDeleteIntegrationAction(
            @SuppressWarnings("unused") com.wazuh.contentmanager.engine.services.EngineService engine) {}

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the delete endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.INTEGRATIONS_URI + "/{id}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the REST request for deleting an integration.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the delete operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        request.param("id");
        this.nodeClient = client;
        this.setPolicyHashService(new PolicyHashService(client));
        this.setIntegrationsContentIndex(new ContentIndex(client, CTI_INTEGRATIONS_INDEX, null));
        this.setSecurityAnalyticsService(new SecurityAnalyticsServiceImpl(client));
        return channel -> channel.sendResponse(this.handleRequest(request).toBytesRestResponse());
    }

    /**
     * @param policyHashService the policy hash service to set
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    /**
     * Setter for the integrations index, used in tests.
     *
     * @param integrationsIndex the integrations index ContentIndex object
     */
    public void setIntegrationsContentIndex(ContentIndex integrationsIndex) {
        this.integrationsIndex = integrationsIndex;
    }

    /**
     * @param service the security analytics service to set
     */
    public void setSecurityAnalyticsService(SecurityAnalyticsService service) {
        this.service = service;
    }

    /**
     * Setter for the node client, used in tests.
     *
     * @param nodeClient the node client to set
     */
    public void setNodeClient(NodeClient nodeClient) {
        this.nodeClient = nodeClient;
    }

    /**
     * Handles the incoming DELETE integration request.
     *
     * @param request incoming request
     * @return a RestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public RestResponse handleRequest(RestRequest request) throws IOException {
        String id = request.param("id");
        this.log.debug("DELETE integration request received (id={}, uri={})", id, request.uri());

        // Check if ID is provided
        if (id == null || id.isEmpty()) {
            this.log.warn("Request rejected: integration ID is required");
            return new RestResponse("Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Check if security analytics service exists
        if (this.service == null) {
            this.log.error("Security Analytics service instance is null");
            return new RestResponse(
                    "Security Analytics service instance is null.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Verify integration exists and is in draft space
        String prefixedId = "d_" + id;
        GetRequest getRequest = new GetRequest(CTI_INTEGRATIONS_INDEX, prefixedId);
        GetResponse getResponse;
        try {
            getResponse = this.nodeClient.get(getRequest).actionGet();
        } catch (Exception e) {
            this.log.error("Failed to retrieve existing integration (id={})", id, e);
            return new RestResponse(
                    "Failed to retrieve existing integration.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        if (!getResponse.isExists()) {
            this.log.warn("Request rejected: integration not found (id={})", id);
            return new RestResponse("Integration not found: " + id, RestStatus.NOT_FOUND.getStatus());
        }

        // Verify integration is in draft space
        Map<String, Object> existingSource = getResponse.getSourceAsMap();
        if (existingSource.containsKey("space")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> space = (Map<String, Object>) existingSource.get("space");
            String spaceName = (String) space.get("name");
            if (!DRAFT_SPACE_NAME.equals(spaceName)) {
                this.log.warn(
                        "Request rejected: cannot delete integration in space '{}' (id={})", spaceName, id);
                return new RestResponse(
                        "Cannot delete integration from space '"
                                + spaceName
                                + "'. Only 'draft' space is modifiable.",
                        RestStatus.BAD_REQUEST.getStatus());
            }
        } else {
            this.log.warn("Request rejected: integration has undefined space (id={})", id);
            return new RestResponse(
                    "Cannot delete integration with undefined space.", RestStatus.BAD_REQUEST.getStatus());
        }

        try {
            // Delete integration from Security Analytics Plugin
            this.log.debug("Deleting integration from Security Analytics (id={})", id);
            try {
                this.service.deleteIntegration(id);
            } catch (Exception e) {
                this.log.warn(
                        "Failed to delete integration [{}] from Security Analytics Plugin: {}",
                        id,
                        e.getMessage());
            }

            // Delete from CTI integrations index
            this.log.debug("Deleting integration from {} (id={})", CTI_INTEGRATIONS_INDEX, prefixedId);
            this.integrationsIndex.delete(prefixedId);

            // Update the space's hash in the policy
            this.log.debug(
                    "Recalculating space hash for draft space after integration deletion (id={})", id);

            this.policyHashService.calculateAndUpdate(
                    CTI_POLICIES_INDEX,
                    CTI_INTEGRATIONS_INDEX,
                    CTI_DECODERS_INDEX,
                    CTI_KVDBS_INDEX,
                    CTI_RULES_INDEX,
                    List.of(Space.DRAFT.toString()));

            this.log.info("Integration deleted successfully (id={})", prefixedId);
            return new RestResponse(
                    "Integration deleted successfully with ID: " + id, RestStatus.OK.getStatus());
        } catch (Exception e) {
            this.log.error("Unexpected error deleting integration (id={})", id, e);
            return new RestResponse(
                    "Unexpected error during processing.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
