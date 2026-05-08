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
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.CredentialsIndex;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/_content_manager/subscription
 *
 * <p>Removes the stored CTI credentials: clears the credentials document inside {@code
 * .wazuh-cti-credentials} and clears the in-memory token in {@link PluginSettings}. The index
 * itself is preserved.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Credentials removed successfully.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestDeleteSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_delete";
    private final CredentialsIndex credentialsIndex;

    /**
     * Create a new REST action.
     *
     * @param credentialsIndex the index used to persist and delete the access token
     */
    public RestDeleteSubscriptionAction(CredentialsIndex credentialsIndex) {
        this.credentialsIndex = credentialsIndex;
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.SUBSCRIPTION_URI)
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(this.handleRequest());
    }

    /**
     * Deletes the credentials document and clears the in-memory access token.
     *
     * @return a {@link BytesRestResponse} representing the operation result
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            this.credentialsIndex.deleteDocument();
            PluginSettings.getInstance().setAccessToken(null);
            RestResponse response = new RestResponse("Credentials removed", RestStatus.OK.getStatus());
            return new BytesRestResponse(RestStatus.OK, response.toXContent());
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
