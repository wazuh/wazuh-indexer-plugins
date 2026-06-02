/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/update
 *
 * <p>Triggers a CTI content update operation.
 *
 * <p>Possible HTTP responses: - 202 Accepted: Update request accepted for processing. - 409
 * Conflict: A content update is already in progress. - 500 Internal Server Error: Unexpected error
 * during processing.
 */
public class RestPostUpdateAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_update";

    private final CatalogSyncJob catalogSyncJob;

    /**
     * Constructs a new RestPostUpdateAction.
     *
     * @param catalogSyncJob the catalog synchronization job to trigger updates.
     */
    public RestPostUpdateAction(CatalogSyncJob catalogSyncJob) {
        this.catalogSyncJob = catalogSyncJob;
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
        return List.of(new Route(POST, PluginSettings.UPDATE_URI));
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(this.handleRequest());
    }

    /**
     * Executes the update operation.
     *
     * @return a BytesRestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            // 1. Conflict check, reject if a sync is already running (409 Conflict)
            if (this.catalogSyncJob.isRunning()) {
                RestResponse error =
                        new RestResponse(
                                "A content update is already in progress.", RestStatus.CONFLICT.getStatus());
                return new BytesRestResponse(RestStatus.CONFLICT, error.toXContent());
            }

            // 2. Trigger the catalog sync and return 202 Accepted
            this.catalogSyncJob.trigger();
            RestResponse response =
                    new RestResponse(
                            "The update request has been accepted for processing.",
                            RestStatus.ACCEPTED.getStatus());
            return new BytesRestResponse(RestStatus.ACCEPTED, response.toXContent());
        } catch (Exception e) {
            RestResponse error =
                    new RestResponse(
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : "An unexpected error occurred while processing your request.",
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent());
        }
    }
}
