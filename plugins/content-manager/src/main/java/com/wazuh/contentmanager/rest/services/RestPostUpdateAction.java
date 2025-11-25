package com.wazuh.contentmanager.rest.services;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.rest.model.RestResponse;
import org.opensearch.transport.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;

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

    public RestPostUpdateAction(CtiConsole console) {
        this.ctiConsole = console;
    }

    @Override
    public String getName() { return ENDPOINT_NAME; }

    @Override
    public List<Route> routes() {
        return List.of(
            // POST /_plugins/content-manager/update
            new NamedRoute.Builder()
                .path(ContentManagerPlugin.UPDATE_URI)
                .method(POST)
                .uniqueName(ENDPOINT_UNIQUE_NAME)
                .build()
        );
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                // 1. Check if Token exists (404 Not Found)
                if (this.ctiConsole.getToken() == null) {
                    RestResponse error = new RestResponse(
                        "Token not found. Please create a subscription before attempting to update.",
                        RestStatus.NOT_FOUND.getStatus()
                    );
                    channel.sendResponse(new BytesRestResponse(RestStatus.NOT_FOUND, error.toXContent()));
                    return;
                }

                // 2. Conflict Check (409 Conflict)
                // TODO: Implement actual concurrency control
                if (1 == 2) {
                    RestResponse error = new RestResponse(
                        "An update operation is already in progress. Please wait for it to complete.",
                        RestStatus.CONFLICT.getStatus()
                    );
                    channel.sendResponse(new BytesRestResponse(RestStatus.CONFLICT, error.toXContent()));
                    return;
                }

                // 3. Rate Limit Check (429 Too Many Requests)
                /**
                 * - X-RateLimit-Limit: Maximum number of requests allowed per hour
                 * - X-RateLimit-Remaining: Number of requests remaining in current window
                 * - X-RateLimit-Reset: Unix timestamp when the rate limit window resets
                 */

                // TODO: Add actual update logic
                RestResponse response = new RestResponse("Update accepted", RestStatus.ACCEPTED.getStatus());
                channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, response.toXContent()));
            } catch (Exception e) {
                RestResponse error = new RestResponse(
                    e.getMessage() != null ? e.getMessage() : "An unexpected error occurred while processing your request.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus()
                );
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent()));
            }
        };
    }
}
