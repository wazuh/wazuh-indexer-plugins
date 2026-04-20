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
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.LogtestService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/logtest/detection
 *
 * <p>Validates the incoming request, ensures the required {@code space}, {@code integration}, and
 * {@code input} fields are present and valid, then delegates execution to {@link
 * LogtestService#executeDetection(String, Space, JsonNode)}. The response contains only the
 * Security Analytics Plugin (SAP) Sigma rule evaluation results.
 */
public class RestPostLogtestDetectionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_logtest_detection";
    private static final String ENDPOINT_UNIQUE_NAME =
            "plugin:content_manager/engine_logtest_detection";

    private final LogtestService logtestService;
    private final PayloadValidations payloadValidations;

    /**
     * Constructs a new RestPostLogtestDetectionAction.
     *
     * @param logtestService the service that orchestrates SA evaluation
     */
    public RestPostLogtestDetectionAction(LogtestService logtestService) {
        this.logtestService = logtestService;
        this.payloadValidations = new PayloadValidations();
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the detection endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.LOGTEST_DETECTION_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Handles incoming requests by delegating to {@link #handleRequest(RestRequest)}.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the detection response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        RestResponse response = this.handleRequest(request);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    /**
     * Validates the request and delegates detection execution to {@link LogtestService}.
     *
     * <p>Validation steps:
     *
     * <ol>
     *   <li>Request has content
     *   <li>Content is valid JSON
     *   <li>Required fields {@code space}, {@code integration}, and {@code input} are present
     *   <li>Space value is {@code "test"} or {@code "standard"}
     *   <li>Input is a JSON object
     * </ol>
     *
     * @param request the incoming REST request
     * @return a {@link RestResponse} with the SAP detection result, or an error response
     */
    public RestResponse handleRequest(RestRequest request) {
        // 1. Check request's payload exists
        RestResponse validationError = this.payloadValidations.validateRequestHasContent(request);
        if (validationError != null) return validationError;

        // 2. Parse JSON
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = mapper.readTree(request.content().streamInput());
        } catch (IOException ex) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // 3. Validate required fields: space, integration, input
        validationError =
                this.payloadValidations.validateRequiredFields(
                        jsonNode, List.of(Constants.KEY_SPACE, Constants.KEY_INTEGRATION, Constants.KEY_INPUT));
        if (validationError != null) return validationError;

        String space = jsonNode.get(Constants.KEY_SPACE).asText();

        // 4. Validate space is "test" or "standard"
        Space spaceEnum;
        try {
            spaceEnum = Space.fromValue(space);
        } catch (IllegalArgumentException e) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INVALID_SPACE, space),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        if (spaceEnum != Space.TEST && spaceEnum != Space.STANDARD) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INVALID_SPACE, space),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // 5. Extract integration and input
        String integrationId = jsonNode.get(Constants.KEY_INTEGRATION).asText();
        JsonNode inputEvent = jsonNode.get(Constants.KEY_INPUT);

        // 6. Validate input is a JSON object
        if (!inputEvent.isObject()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INVALID_FIELD_FORMAT, Constants.KEY_INPUT),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // 7. Delegate execution to Service
        return this.logtestService.executeDetection(integrationId, spaceEnum, inputEvent);
    }
}
