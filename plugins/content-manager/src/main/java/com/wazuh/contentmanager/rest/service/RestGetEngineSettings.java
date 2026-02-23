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
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * GET /_plugins/_content_manager/engine_settings
 *
 * <p>Retrieves the current engine configuration settings from the {@code .wazuh-settings} index. If
 * no settings document has been written yet, returns the default configuration.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Returns the settings document (or defaults if not yet persisted)
 *   <li>500 Internal Server Error: Index read operation failed
 * </ul>
 */
public class RestGetEngineSettings extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestGetEngineSettings.class);
    private static final String ENDPOINT_NAME = "content_manager_engine_settings_get";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/engine_settings_get";

    private static final ObjectMapper mapper = new ObjectMapper();

    private final ContentIndex settingsIndex;

    /**
     * Construct the REST handler.
     *
     * @param settingsIndex the ContentIndex wrapping {@code .wazuh-settings}
     */
    public RestGetEngineSettings(ContentIndex settingsIndex) {
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
     * @return route configuration for the engine settings retrieval endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.ENGINE_SETTINGS_URI)
                        .method(RestRequest.Method.GET)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepare the request by returning a consumer that reads the settings and sends the response.
     *
     * @param request the incoming REST request
     * @param client the node client (unused, required by framework)
     * @return a RestChannelConsumer that produces the response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(handleRequest());
    }

    /**
     * Execute the get-engine-settings operation.
     *
     * @return a BytesRestResponse containing the settings or defaults
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            JsonNode document = this.settingsIndex.getDocument(RestPutEngineSettings.SETTINGS_ID);
            if (document == null) {
                return buildDefaultResponse();
            }
            return new BytesRestResponse(
                    RestStatus.OK, "application/json", mapper.writeValueAsBytes(document));
        } catch (Exception e) {
            log.error("Failed to retrieve engine settings: {}", e.getMessage(), e);
            return new RestResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                    .toBytesRestResponse();
        }
    }

    /** Build a response containing the default settings (engine.index_raw_events = false). */
    private BytesRestResponse buildDefaultResponse() throws IOException {
        ObjectNode defaults = mapper.createObjectNode();
        ObjectNode engine = mapper.createObjectNode();
        engine.put(Constants.KEY_INDEX_RAW_EVENTS, false);
        defaults.set(Constants.KEY_ENGINE, engine);
        return new BytesRestResponse(
                RestStatus.OK, "application/json", mapper.writeValueAsBytes(defaults));
    }
}
