/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import com.wazuh.contentmanager.updater.ContentUpdater;

import static org.opensearch.rest.RestRequest.Method.GET;
import static com.wazuh.contentmanager.settings.PluginSettings.API_BASE_URI;

/** A test class that creates a "/updater" endpoint that triggers a content update */
public class UpdaterHandler extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(UpdaterHandler.class);

    public static final String NAME = "content_updater";

    /** Exposes the endpoint */
    @Override
    public List<RestHandler.Route> routes() {
        return List.of(new RestHandler.Route(GET, API_BASE_URI + "/updater"));
    }

    @Override
    public String getName() {
        return NAME;
    }

    /** Handles the REST request and calls the appropriate action */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        // TODO: Remove on JobScheduler implementation.
        if (Objects.requireNonNull(request.method()) == GET) {
            ContentUpdater updater = new ContentUpdater(client);
            // Run the update process asynchronously
            CompletableFuture.runAsync(
                    () -> {
                        try {
                            updater.fetchAndApplyUpdates(Long.parseLong(request.param("from_offset")));
                        } catch (ContentUpdater.ContentUpdateException e) {
                            // Log the error (using OpenSearch logger if available)
                            log.error("Error updating content: {}", e.getMessage());
                        }
                    });
            return channel ->
                    channel.sendResponse(
                            new BytesRestResponse(RestStatus.ACCEPTED, "Content update started"));
        }
        throw new IllegalArgumentException(("Unsupported HTTP method " + request.method().name()));
    }
}
