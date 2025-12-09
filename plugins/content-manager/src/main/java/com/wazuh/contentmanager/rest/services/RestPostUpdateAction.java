package com.wazuh.contentmanager.rest.services;

import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/content-manager/update
 *
 * Triggers a CTI content update operation.
 *
 * Possible HTTP responses:
 * - 202 Accepted: Update operation accepted and started
 * - 404 Not Found: No subscription exists (subscription required before updating)
 * - 401 Unauthorized: The endpoint is being accessed by a different user, the expected user is wazuh-server
 * - 409 Conflict: Another update operation is already in progress
 * - 429 Too Many Requests: Rate limit exceeded
 * - 500 Internal Server Error: Unexpected error during processing
 *
 * Response headers (for rate limiting):
 * - X-RateLimit-Limit: Maximum number of requests allowed per hour
 * - X-RateLimit-Remaining: Number of requests remaining in current window
 * - X-RateLimit-Reset: Unix timestamp when the rate limit window resets
 */
public class RestPostUpdateAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_update";
    private final CtiConsole ctiConsole;
    private final CatalogSyncJob catalogSyncJob;

    public RestPostUpdateAction(CtiConsole console, CatalogSyncJob catalogSyncJob) {
        this.ctiConsole = console;
        this.catalogSyncJob = catalogSyncJob;
    }

    /**
     * Return a short identifier for this handler.
     */
    @Override
    public String getName() { return ENDPOINT_NAME; }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the update endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
            // POST /_plugins/content-manager/update
            new NamedRoute.Builder()
                .path(PluginSettings.UPDATE_URI)
                .method(POST)
                .uniqueName(ENDPOINT_UNIQUE_NAME)
                .build()
        );
    }

    /**
     * Prepare the request by returning a consumer that executes the update operation.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            channel.sendResponse(this.handleRequest());
        };
    }

    /**
     * Execute the update operation.
     *
     * @return a BytesRestResponse describing the outcome
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            // 1. Check if Token exists (404 Not Found)
            if (this.ctiConsole.getToken() == null) {
                RestResponse error = new RestResponse(
                    "Token not found. Please create a subscription before attempting to update.",
                    RestStatus.NOT_FOUND.getStatus()
                );
                return new BytesRestResponse(RestStatus.NOT_FOUND, error.toXContent());
            }

            // 2. Conflict Check (409 Conflict)
            if (this.catalogSyncJob.isRunning()) {
                RestResponse error = new RestResponse(
                    "An update operation is already in progress. Please wait for it to complete.",
                    RestStatus.CONFLICT.getStatus()
                );
                return new BytesRestResponse(RestStatus.CONFLICT, error.toXContent());
            }

            // 3. Rate Limit Check (429 Too Many Requests)
            /**
             * - X-RateLimit-Limit: Maximum number of requests allowed per hour
             * - X-RateLimit-Remaining: Number of requests remaining in current window
             * - X-RateLimit-Reset: Unix timestamp when the rate limit window resets
             */

            // 4. Update Accepted (202 ACCEPTED)
            this.catalogSyncJob.trigger();
            RestResponse response = new RestResponse("Update accepted", RestStatus.ACCEPTED.getStatus());
            return new BytesRestResponse(RestStatus.ACCEPTED, response.toXContent());
        } catch (Exception e) {
            RestResponse error = new RestResponse(
                e.getMessage() != null ? e.getMessage() : "An unexpected error occurred while processing your request.",
                RestStatus.INTERNAL_SERVER_ERROR.getStatus()
            );
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent());
        }
    }
}
