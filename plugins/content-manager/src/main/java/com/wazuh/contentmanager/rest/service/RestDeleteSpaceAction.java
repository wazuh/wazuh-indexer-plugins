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
package com.wazuh.contentmanager.rest.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.MockSecurityAnalyticsService;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/_content_manager/space/{space}
 *
 * <p>Resets the draft user space to its initial state by deleting all associated documents and
 * re-generating the default policy.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Space reset successfully.
 *   <li>400 Bad Request: Missing space parameter, invalid space string, or attempting to reset a
 *       space different from draft.
 *   <li>500 Internal Server Error: Engine unavailable, bulk deletion failure, or unexpected error.
 * </ul>
 */
public class RestDeleteSpaceAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestDeleteSpaceAction.class);
    private static final String ENDPOINT_NAME = "content_manager_space_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/space_delete";

    private SpaceService spaceService;
    private SecurityAnalyticsService securityAnalyticsService;

    public RestDeleteSpaceAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.SPACE_URI + "/{space}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        // Consume path parameter early to avoid unrecognized parameter errors
        if (request.hasParam(Constants.KEY_SPACE)) {
            request.param(Constants.KEY_SPACE);
        }

        this.spaceService = new SpaceService(client);

        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            this.securityAnalyticsService = new MockSecurityAnalyticsService();
        } else {
            this.securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        }

        return channel -> {
            RestResponse response = this.handleRequest(request);
            channel.sendResponse(response.toBytesRestResponse());
        };
    }

    /**
     * Handles the space reset logic: 1. Validates the space parameter and ensures it is draft. 2.
     * Fetches current resources for the space to perform necessary external deletions in SAP. 3.
     * Deletes all documents associated with the space across all resource indices. 4. Re-generates
     * the default policy for the space. 5. Returns appropriate HTTP responses based on the outcome of
     * each operation. Note: External deletions in SAP are attempted but do not block the reset
     * process if they fail, as the primary goal is to ensure the space is reset in the content
     * manager. Failures in external deletions are logged for monitoring and troubleshooting purposes.
     *
     * @param request The incoming REST request containing the space parameter.
     * @return A RestResponse indicating the success or failure of the space reset operation, with
     *     appropriate status codes and messages.
     */
    public RestResponse handleRequest(RestRequest request) {
        String spaceParam = request.param(Constants.KEY_SPACE);

        Space space;
        try {
            space = Space.fromValue(spaceParam);
        } catch (IllegalArgumentException e) {
            return new RestResponse(
                    "Invalid space: [" + spaceParam + "].", RestStatus.BAD_REQUEST.getStatus());
        }

        if (space != Space.DRAFT) {
            return new RestResponse(
                    "Cannot reset the '" + space + "' space.", RestStatus.BAD_REQUEST.getStatus());
        }

        try {
            log.info("Starting reset operation for space [{}]", space);

            // Note: space is always DRAFT.
            // 1. Remove resources belonging to space in the .cti-* indices
            this.spaceService.deleteSpaceResources(space);
            // 2. Remove resources belonging to the space in Security Analytics.
            this.securityAnalyticsService.deleteSpaceResources(space);

            // Re-generate the default policy for the space
            String sharedDocumentId =
                    UUID.nameUUIDFromBytes("wazuh-default-policy".getBytes(StandardCharsets.UTF_8))
                            .toString();
            this.spaceService.initializeSpace(space.toString(), sharedDocumentId);

            String message = String.format(Locale.ROOT, "Successfully reset space [%s].", space);
            log.info(message);
            return new RestResponse(message, RestStatus.OK.getStatus());
        } catch (Exception e) {
            log.error("Failed to reset space [{}]: {}", space, e.getMessage());
            return new RestResponse(
                    "Internal Server Error: " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Setter for spaceService to allow injection in tests.
     *
     * @param spaceService instance of SpaceService, for resources removal in the content manager and
     *     policy re-generation/reload.
     */
    void setSpaceService(SpaceService spaceService) {
        this.spaceService = spaceService;
    }

    /**
     * Setter for securityAnalyticsService to allow injection in tests.
     *
     * @param securityAnalyticsService instance of SecurityAnalyticsService, for resources removal in
     *     the Security Analytics plugin.
     */
    void setSecurityAnalyticsService(SecurityAnalyticsService securityAnalyticsService) {
        this.securityAnalyticsService = securityAnalyticsService;
    }
}
