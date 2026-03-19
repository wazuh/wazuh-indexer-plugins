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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.setup.index.SettingsIndex;
import com.wazuh.setup.model.WazuhSettings;

/**
 * PUT /_plugins/_setup/settings
 *
 * <p>Persists configuration settings to the {@code .wazuh-settings} index. Currently supports the
 * {@code engine.index_raw_events} boolean flag which controls whether the Engine indexes raw events
 * into the {@code wazuh-events-raw-v5} data stream.
 *
 * <p>Expected request body:
 *
 * <pre>{@code {"engine": {"index_raw_events": true}}}</pre>
 */
public class RestPutSettingsAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPutSettingsAction.class);
    private static final String ENDPOINT_NAME = "wazuh_settings";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:wazuh/settings";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final SettingsIndex settingsIndex;

    /**
     * Construct the REST handler.
     *
     * @param settingsIndex the settings service managing the {@code .wazuh-settings} index
     */
    public RestPutSettingsAction(SettingsIndex settingsIndex) {
        this.settingsIndex = settingsIndex;
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
                        .path(SettingsIndex.SETTINGS_URI)
                        .build());
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> this.handleRequest(request, channel);
    }

    /**
     * Execute the put-settings operation asynchronously.
     *
     * @param request the incoming REST request
     * @param channel the REST channel for sending the response
     */
    public void handleRequest(RestRequest request, RestChannel channel) {
        // 1. Validate content presence
        if (!request.hasContent()) {
            sendResponse(
                    channel,
                    new RestResponse(
                            SettingsIndex.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus()));
            return;
        }

        // 2. Parse JSON
        String payload = request.content().utf8ToString();
        JsonNode root;
        try {
            root = MAPPER.readTree(payload);
        } catch (Exception e) {
            sendResponse(
                    channel,
                    new RestResponse(
                            SettingsIndex.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus()));
            return;
        }

        // 3. Validate structure using model method
        String validationError = WazuhSettings.validate(root);
        if (validationError != null) {
            sendResponse(channel, new RestResponse(validationError, RestStatus.BAD_REQUEST.getStatus()));
            return;
        }

        // 4. Parse into model and persist asynchronously
        WazuhSettings settings = WazuhSettings.fromPayload(root);
        this.settingsIndex.indexDocument(
                settings,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        log.info("Wazuh settings updated: {}", settings);
                        sendResponse(
                                channel,
                                new RestResponse(SettingsIndex.S_200_SETTINGS_UPDATED, RestStatus.OK.getStatus()));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to persist settings: {}", e.getMessage(), e);
                        sendResponse(
                                channel,
                                new RestResponse(
                                        SettingsIndex.E_500_INTERNAL_SERVER_ERROR,
                                        RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                    }
                });
    }

    /**
     * Sends a RestResponse through the channel.
     *
     * @param channel the REST channel
     * @param response the response to send
     */
    private static void sendResponse(RestChannel channel, RestResponse response) {
        try {
            channel.sendResponse(response.toBytesRestResponse());
        } catch (Exception e) {
            log.error("Failed to send response: {}", e.getMessage(), e);
            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
        }
    }
}
