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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * PUT /_plugins/_content_manager/engine_settings
 *
 * <p>Persists engine configuration settings to the {@code .wazuh-settings} index. Currently
 * supports the {@code engine.index_raw_events} boolean flag which controls whether the Engine
 * writes incoming events to the {@code wazuh-events-raw-v5} data stream before enrichment.
 *
 * <p>Expected request body:
 *
 * <pre>{@code {"engine": {"index_raw_events": true}}}</pre>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Settings persisted successfully
 *   <li>400 Bad Request: Missing or invalid payload
 *   <li>500 Internal Server Error: Index operation failed
 * </ul>
 */
public class RestPutEngineSettings extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutEngineSettings.class);
    private static final String ENDPOINT_NAME = "content_manager_engine_settings";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/engine_settings";
    private final ContentIndex settingsIndex;
    private final PayloadValidations payloadValidations = new PayloadValidations();
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Construct the REST handler.
     *
     * @param settingsIndex the ContentIndex wrapping {@code .wazuh-settings}
     */
    public RestPutEngineSettings(ContentIndex settingsIndex) {
        this.settingsIndex = settingsIndex;
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the engine settings update endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .method(RestRequest.Method.PUT)
                        .path(PluginSettings.ENGINE_SETTINGS_URI)
                        .build());
    }

    /**
     * Handle the incoming request and send the response.
     *
     * @param request the incoming REST request
     * @param client the node client (unused, required by framework)
     * @return a RestChannelConsumer that produces the response
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        return channel -> {
            RestResponse response = this.handleRequest(request);
            channel.sendResponse(response.toBytesRestResponse());
        };
    }

    /**
     * Execute the put-engine-settings operation.
     *
     * @param request the incoming REST request
     * @return a RestResponse with the result
     */
    public RestResponse handleRequest(RestRequest request) {
        // 1. Validate content presence
        RestResponse contentCheck = this.payloadValidations.validateRequestHasContent(request);
        if (contentCheck != null) {
            return contentCheck;
        }

        // 2. Parse and validate JSON structure
        String payload = request.content().utf8ToString();
        JsonNode root;
        try {
            root = mapper.readTree(payload);
        } catch (Exception e) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        JsonNode engineNode = root.get(Constants.KEY_ENGINE);
        if (engineNode == null || !engineNode.isObject()) {
            return new RestResponse(
                    Constants.E_400_MISSING_ENGINE_SETTINGS, RestStatus.BAD_REQUEST.getStatus());
        }

        JsonNode indexRawEventsNode = engineNode.get(Constants.KEY_INDEX_RAW_EVENTS);
        if (indexRawEventsNode == null || !indexRawEventsNode.isBoolean()) {
            return new RestResponse(
                    Constants.E_400_MISSING_ENGINE_SETTINGS, RestStatus.BAD_REQUEST.getStatus());
        }

        // 3. Build sanitized payload and persist to .wazuh-settings
        try {
            ObjectNode cleanPayload = mapper.createObjectNode();
            cleanPayload.set(Constants.KEY_ENGINE, engineNode);
            this.settingsIndex.indexDocument(PluginSettings.ENGINE_SETTINGS_ID, cleanPayload);
            log.info("Engine settings updated: {}", cleanPayload);
            return new RestResponse(Constants.S_200_SETTINGS_UPDATED, RestStatus.OK.getStatus());
        } catch (Exception e) {
            log.error("Failed to persist engine settings: {}", e.getMessage(), e);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
