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

import com.fasterxml.jackson.databind.JsonNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.contentmanager.action.PutPolicyAction;
import com.wazuh.contentmanager.action.PutPolicyRequest;
import com.wazuh.contentmanager.action.PutPolicyResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * REST handler for updating policy resources on the Wazuh Engine.
 *
 * <p>This endpoint handles PUT requests to update policy configurations in the draft or standard
 * space. The actual write is delegated to {@link PutPolicyAction} so the security plugin enforces
 * authorization, and the {@code plugins.content_manager.sensitive_config.locked} setting can block
 * the operation. When the transport action reports a standard-space hash change, this handler
 * reloads the standard space into the Engine (best effort).
 */
public class RestPutPolicyAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutPolicyAction.class);
    private static final String ENDPOINT_NAME = "content_manager_policy_update";

    private SpaceService spaceService;
    private EngineService engineService;

    /**
     * Constructs a new RestPutPolicyAction handler.
     *
     * @param spaceService The space service instance used to build the Engine payload.
     * @param engineService The engine service instance for loading policies into the Engine.
     */
    public RestPutPolicyAction(SpaceService spaceService, EngineService engineService) {
        this.spaceService = spaceService;
        this.engineService = engineService;
    }

    /**
     * Setter for the space service, used in tests.
     *
     * @param spaceService the space service instance to set
     */
    public void setSpaceService(SpaceService spaceService) {
        this.spaceService = spaceService;
    }

    /**
     * Setter for the engine service, used in tests.
     *
     * @param engineService the engine service instance to set
     */
    public void setEngineService(EngineService engineService) {
        this.engineService = engineService;
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
        return List.of(new Route(PUT, PluginSettings.POLICY_URI + "/{space}"));
    }

    /**
     * Delegates the policy update to {@link PutPolicyAction}, then reloads the Engine when required.
     *
     * @param request the incoming REST request containing the policy payload
     * @param client the node client used to execute the transport action
     * @return a consumer that sends the policy update response
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String space = request.param(Constants.KEY_SPACE);
        String payload = request.hasContent() ? request.content().utf8ToString() : null;
        PutPolicyRequest putPolicyRequest = new PutPolicyRequest(space, payload);
        return channel ->
                client.execute(
                        PutPolicyAction.INSTANCE,
                        putPolicyRequest,
                        new RestResponseListener<PutPolicyResponse>(channel) {
                            @Override
                            public org.opensearch.rest.RestResponse buildResponse(PutPolicyResponse response) {
                                if (response.shouldReloadEngine()) {
                                    loadStandardSpaceIntoEngine();
                                }
                                return new RestResponse(response.getMessage(), response.getStatus().getStatus())
                                        .toBytesRestResponse();
                            }
                        });
    }

    /**
     * Builds the engine payload for the standard space and loads it into the Engine. Best effort:
     * failures are logged but do not affect the policy update response.
     */
    private void loadStandardSpaceIntoEngine() {
        if (this.engineService == null) {
            log.warn(Constants.E_LOG_ENGINE_IS_NULL);
            return;
        }
        try {
            JsonNode payload = this.spaceService.buildEnginePayload(Space.STANDARD.toString());
            RestResponse response = this.engineService.promote(payload);
            if (response.getStatus() == RestStatus.OK.getStatus()) {
                log.info("Engine load for standard space completed successfully.");
            } else {
                log.warn(
                        "Engine load for standard space returned status [{}]: {}",
                        response.getStatus(),
                        response.getMessage());
            }
        } catch (Exception e) {
            log.error("Failed to load standard space into Engine: {}", e.getMessage());
        }
    }
}
