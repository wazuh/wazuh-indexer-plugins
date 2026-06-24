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

import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.setup.action.PutSettingsAction;
import com.wazuh.setup.action.PutSettingsRequest;
import com.wazuh.setup.action.PutSettingsResponse;
import com.wazuh.setup.index.SettingsIndex;

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
 *
 * <p>The write is delegated to {@link PutSettingsAction} so the security plugin enforces
 * authorization, and the {@code plugins.setup.settings_update.enabled} setting can block the
 * operation.
 */
public class RestPutSettingsAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "wazuh_settings";

    /** Default constructor. */
    public RestPutSettingsAction() {}

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.PUT, SettingsIndex.SETTINGS_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String payload = request.hasContent() ? request.content().utf8ToString() : null;
        PutSettingsRequest putSettingsRequest = new PutSettingsRequest(payload);
        return channel ->
                client.execute(
                        PutSettingsAction.INSTANCE,
                        putSettingsRequest,
                        new RestResponseListener<PutSettingsResponse>(channel) {
                            @Override
                            public org.opensearch.rest.RestResponse buildResponse(PutSettingsResponse response) {
                                return new RestResponse(response.getMessage(), response.getStatus().getStatus())
                                        .toBytesRestResponse();
                            }
                        });
    }
}
