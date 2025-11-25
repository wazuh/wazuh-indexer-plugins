package com.wazuh.contentmanager.rest.services;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.rest.model.ErrorResponse;
import com.wazuh.contentmanager.services.ContentManagerService;
import org.opensearch.transport.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
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
 * - 429 Too Many Requests: Rate limit exceeded (includes X-RateLimit-* headers)
 * - 503 Service Unavailable: External CTI service is unavailable
 * - 500 Internal Server Error: Unexpected error during processing
 *
 * Response headers (for rate limiting):
 * - X-RateLimit-Limit: Maximum number of requests allowed per hour
 * - X-RateLimit-Remaining: Number of requests remaining in current window
 * - X-RateLimit-Reset: Unix timestamp when the rate limit window resets
 */
public class RestPostUpdateAction extends BaseRestHandler {
    private final ContentManagerService service;
    private static final String ENDPOINT_NAME = "content_manager_subscription_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_update";

    // TODO: Delete once real concurrency control is implemented
    // Mechanism for conflict testing
    private volatile boolean isUpdateInProgress = false;

    private static final long DEFAULT_UPDATE_DURATION_MS = 0;

    /**
        * Hidden header used to control the simulated duration from integration tests.
        * Allows artificially extending the processing time to test race conditions.
     */
    public static final String TEST_HEADER_DURATION = "X-Wazuh-Test-Simulated-Duration";

    // TODO: Remove this temporary mechanism once the actual external service is implemented
    // This is only for testing the 503 Service Unavailable error
    // Set this to true to simulate an external service failure
    private static final boolean SIMULATE_EXTERNAL_SERVICE_ERROR = false;

    public RestPostUpdateAction(ContentManagerService service) {
        this.service = service;
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
                // 1. Check if subscription exists (404 Not Found)
                if (service.getSubscription() == null) {
                    ErrorResponse error = new ErrorResponse(
                        "Subscription not found. Please create a subscription before attempting to update.",
                        RestStatus.NOT_FOUND.getStatus()
                    );
                    XContentBuilder builder = XContentFactory.jsonBuilder();
                    builder.startObject()
                        .field("message", error.getMessage())
                        .field("status", error.getStatus())
                        .endObject();
                    channel.sendResponse(new BytesRestResponse(RestStatus.NOT_FOUND, builder));
                    return;
                }

                // 2. Conflict Check (409 Conflict)
                // TODO: Implement actual concurrency control
                if (isUpdateInProgress) {
                    ErrorResponse error = new ErrorResponse(
                        "An update operation is already in progress. Please wait for it to complete.",
                        RestStatus.CONFLICT.getStatus()
                    );
                    XContentBuilder builder = XContentFactory.jsonBuilder();
                    builder.startObject()
                        .field("message", error.getMessage())
                        .field("status", error.getStatus())
                        .endObject();
                    channel.sendResponse(new BytesRestResponse(RestStatus.CONFLICT, builder));
                    return;
                }

                // 3. Rate Limit Check (429 Too Many Requests)
                // Allow tests to override the rate limit via the header `X-Wazuh-Test-Rate-Limit`.
                String testRateLimitHeader = request.header("X-Wazuh-Test-Rate-Limit");
                Integer testRateLimit = null;
                if (testRateLimitHeader != null) {
                    try {
                        testRateLimit = Integer.parseInt(testRateLimitHeader);
                    } catch (NumberFormatException ignored) { }
                }

                if (!service.canTriggerUpdate(testRateLimit)) {
                    ErrorResponse error = new ErrorResponse(
                        "Too many update requests. Please try again later.",
                        RestStatus.TOO_MANY_REQUESTS.getStatus()
                    );
                    XContentBuilder builder = XContentFactory.jsonBuilder();
                    builder.startObject()
                        .field("message", error.getMessage())
                        .field("status", error.getStatus())
                        .endObject();
                    BytesRestResponse response = new BytesRestResponse(RestStatus.TOO_MANY_REQUESTS, builder);
                    int effectiveLimit = (testRateLimit != null && testRateLimit > 0) ? testRateLimit : ContentManagerService.getRateLimit();
                    response.addHeader("X-RateLimit-Limit", String.valueOf(effectiveLimit));
                    response.addHeader("X-RateLimit-Remaining", String.valueOf(0));
                    response.addHeader("X-RateLimit-Reset", String.valueOf(service.getRateLimitReset()));
                    channel.sendResponse(response);
                    return;
                }

                // 4. External Service Check (503 Service Unavailable)
                // TODO: Replace this simulation with actual external service availability check
                String simulateExternalError = request.header("X-Wazuh-Test-Simulate-External-Service-Error");
                boolean simulateExternal = (simulateExternalError != null && simulateExternalError.equalsIgnoreCase("true"))
                    || SIMULATE_EXTERNAL_SERVICE_ERROR;

                if (simulateExternal) {
                    ErrorResponse error = new ErrorResponse(
                        "CTI API is currently unavailable. Unable to fetch update information.",
                        RestStatus.SERVICE_UNAVAILABLE.getStatus()
                    );
                    XContentBuilder builder = XContentFactory.jsonBuilder();
                    builder.startObject()
                        .field("message", error.getMessage())
                        .field("status", error.getStatus())
                        .endObject();
                    channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, builder));
                    return;
                }

                // TODO: Replace this simulation with actual update logic
                // Mark update as in progress
                isUpdateInProgress = true;

                // Determine duration
                long simulationDuration = getSimulatedDuration(request);

                // Simulate a long-running update operation
                new Thread(() -> {
                    try {
                        Thread.sleep(simulationDuration);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        isUpdateInProgress = false;
                    }
                }).start();

                XContentBuilder builder = XContentFactory.jsonBuilder();
                builder.startObject()
                    .field("status", "update accepted")
                    .endObject();
                BytesRestResponse response = new BytesRestResponse(RestStatus.ACCEPTED, builder);
                int effectiveLimit = (testRateLimit != null && testRateLimit > 0) ? testRateLimit : ContentManagerService.getRateLimit();
                response.addHeader("X-RateLimit-Limit", String.valueOf(effectiveLimit));
                response.addHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, effectiveLimit - 1)));
                response.addHeader("X-RateLimit-Reset", String.valueOf(service.getRateLimitReset()));
                channel.sendResponse(response);
            } catch (Exception e) {
                ErrorResponse error = new ErrorResponse(
                    e.getMessage() != null ? e.getMessage() : "An unexpected error occurred while processing your request.",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus()
                );
                XContentBuilder builder = XContentFactory.jsonBuilder();
                builder.startObject()
                    .field("message", error.getMessage())
                    .field("status", error.getStatus())
                    .endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder));
            }
        };
    }

    // TODO: Remove this temporary mechanism once the actual external service is implemented
    /**
     * Extracts the simulated duration from the request header.
     * Returns the default duration if the header is missing or invalid.
     */
    private long getSimulatedDuration(RestRequest request) {
        String headerValue = request.header(TEST_HEADER_DURATION);
        if (headerValue != null) {
            try {
                return Long.parseLong(headerValue);
            } catch (NumberFormatException ignored) {
                // Ignore and use default
            }
        }
        return DEFAULT_UPDATE_DURATION_MS;
    }
}
