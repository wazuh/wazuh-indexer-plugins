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
package com.wazuh.setup.rest;

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

import com.wazuh.setup.settings.WazuhSettings;

/**
 * PUT /_plugins/_wazuh/settings
 *
 * <p>Persists configuration settings to the {@code .wazuh-settings} index. Currently supports the
 * {@code engine.index_raw_events} boolean flag which controls whether the Engine writes incoming
 * events to the raw data stream before enrichment.
 *
 * <p>Expected request body:
 *
 * <pre>{@code {"engine": {"index_raw_events": true}}}</pre>
 */
public class RestPutSettingsAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutSettingsAction.class);
    private static final String ENDPOINT_NAME = "wazuh_settings";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:wazuh/settings";
    private static final ObjectMapper mapper = new ObjectMapper();

    private final WazuhSettings wazuhSettings;

    /**
     * Construct the REST handler.
     *
     * @param wazuhSettings the settings service managing the {@code .wazuh-settings} index
     */
    public RestPutSettingsAction(WazuhSettings wazuhSettings) {
        this.wazuhSettings = wazuhSettings;
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .method(RestRequest.Method.PUT)
                        .path(WazuhSettings.SETTINGS_URI)
                        .build());
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        return channel -> {
            RestResponse response = this.handleRequest(request);
            channel.sendResponse(response.toBytesRestResponse());
        };
    }

    /**
     * Execute the put-settings operation.
     *
     * @param request the incoming REST request
     * @return a RestResponse with the result
     */
    public RestResponse handleRequest(RestRequest request) {
        // 1. Validate content presence
        if (!request.hasContent()) {
            return new RestResponse(
                    WazuhSettings.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // 2. Parse and validate JSON structure
        String payload = request.content().utf8ToString();
        JsonNode root;
        try {
            root = mapper.readTree(payload);
        } catch (Exception e) {
            return new RestResponse(
                    WazuhSettings.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        JsonNode engineNode = root.get(WazuhSettings.KEY_ENGINE);
        if (engineNode == null || !engineNode.isObject()) {
            return new RestResponse(
                    WazuhSettings.E_400_MISSING_SETTINGS, RestStatus.BAD_REQUEST.getStatus());
        }

        JsonNode indexRawEventsNode = engineNode.get(WazuhSettings.KEY_INDEX_RAW_EVENTS);
        if (indexRawEventsNode == null || !indexRawEventsNode.isBoolean()) {
            return new RestResponse(
                    WazuhSettings.E_400_MISSING_SETTINGS, RestStatus.BAD_REQUEST.getStatus());
        }

        // 3. Build sanitized payload and persist to .wazuh-settings
        try {
            ObjectNode cleanPayload = mapper.createObjectNode();
            cleanPayload.set(WazuhSettings.KEY_ENGINE, engineNode);
            this.wazuhSettings.indexDocument(mapper.writeValueAsString(cleanPayload));
            log.info("Wazuh settings updated: {}", cleanPayload);
            return new RestResponse(WazuhSettings.S_200_SETTINGS_UPDATED, RestStatus.OK.getStatus());
        } catch (Exception e) {
            log.error("Failed to persist settings: {}", e.getMessage(), e);
            return new RestResponse(
                    WazuhSettings.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
