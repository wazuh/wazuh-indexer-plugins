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
import java.util.Map;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.MockSecurityAnalyticsService;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/_content_manager/space/{space}
 *
 * <p>Resets a user space (draft, test, custom) to its initial state by deleting all associated
 * documents and re-generating the default policy. For the 'test' space, the engine logtest session
 * is also reset.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Space reset successfully.
 *   <li>400 Bad Request: Missing space parameter, invalid space string, or attempting to reset
 *       standard space.
 *   <li>500 Internal Server Error: Engine unavailable, bulk deletion failure, or unexpected error.
 * </ul>
 */
public class RestDeleteSpaceAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestDeleteSpaceAction.class);
    private static final String ENDPOINT_NAME = "content_manager_space_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/space_delete";

    private final EngineService engineService;
    private SpaceService spaceService;
    private SecurityAnalyticsService securityAnalyticsService;

    public RestDeleteSpaceAction(EngineService engineService) {
        this.engineService = engineService;
    }

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

    public RestResponse handleRequest(RestRequest request) {
        String spaceParam = request.param(Constants.KEY_SPACE);

        Space space;
        try {
            space = Space.fromValue(spaceParam);
        } catch (IllegalArgumentException e) {
            return new RestResponse(
                    "Invalid space: [" + spaceParam + "].", RestStatus.BAD_REQUEST.getStatus());
        }

        if (space == Space.STANDARD) {
            return new RestResponse(
                    "Cannot reset the 'standard' space.", RestStatus.BAD_REQUEST.getStatus());
        }

        try {
            log.info("Starting reset operation for space [{}]", space);

            // 1. Fetch current resources to perform external deletions
            Map<String, Map<String, String>> spaceResources =
                    this.spaceService.getSpaceResources(space.toString());

            // 2. Delete SAP resources (Integrations & Rules)
            Map<String, String> rules = spaceResources.get(Constants.KEY_RULES);
            if (rules != null) {
                for (String id : rules.keySet()) {
                    try {
                        this.securityAnalyticsService.deleteRule(id, false);
                        log.debug("Deleted rule [{}] from SAP for space reset", id);
                    } catch (Exception e) {
                        log.warn(
                                "Failed to delete rule [{}] from SAP during space reset: {}", id, e.getMessage());
                    }
                }
            }

            Map<String, String> integrations = spaceResources.get(Constants.KEY_INTEGRATIONS);
            if (integrations != null) {
                for (String id : integrations.keySet()) {
                    try {
                        this.securityAnalyticsService.deleteIntegration(id, false);
                        log.debug("Deleted integration [{}] from SAP for space reset", id);
                    } catch (Exception e) {
                        log.warn(
                                "Failed to delete integration [{}] from SAP during space reset: {}",
                                id,
                                e.getMessage());
                    }
                }
            }

            // 3. Delete all documents associated with the space across all resource indices
            this.spaceService.deleteSpaceResources(space.toString());

            // 4. Re-generate the default policy for the space
            String sharedDocumentId =
                    UUID.nameUUIDFromBytes("wazuh-default-policy".getBytes(StandardCharsets.UTF_8))
                            .toString();
            this.spaceService.initializeSpace(space.toString(), sharedDocumentId);

            // 5. Reset local engine test session if space is test
            if (space == Space.TEST && this.engineService != null) {
                RestResponse engineResponse = this.engineService.deleteLogtest();
                if (engineResponse.getStatus() >= 200 && engineResponse.getStatus() < 300) {
                    log.info("Successfully reset Engine test state.");
                } else {
                    log.error("Failed to reset Engine test state: {}", engineResponse.getMessage());
                    return new RestResponse(
                            "Failed to reset Engine test state: " + engineResponse.getMessage(),
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                }
            }

            log.info("Successfully reset space [{}]", space);

            return new RestResponse("Space reset successfully", RestStatus.OK.getStatus());
        } catch (Exception e) {
            log.error("Failed to reset space [{}]: {}", space, e.getMessage());
            return new RestResponse(
                    "Internal Server Error: " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    void setSpaceService(SpaceService spaceService) {
        this.spaceService = spaceService;
    }

    void setSecurityAnalyticsService(SecurityAnalyticsService securityAnalyticsService) {
        this.securityAnalyticsService = securityAnalyticsService;
    }
}
