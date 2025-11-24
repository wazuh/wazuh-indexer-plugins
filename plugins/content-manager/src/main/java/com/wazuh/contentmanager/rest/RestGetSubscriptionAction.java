package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.model.rest.Subscription;
import com.wazuh.contentmanager.model.rest.Token;
import com.wazuh.contentmanager.model.rest.ErrorResponse;
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

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/content-manager/subscription
 *
 * Retrieves the current CTI subscription token.
 *
 * Possible HTTP responses:
 * - 200 OK: Subscription found, returns access token and token type
 * - 404 Not Found: No subscription exists
 * - 401 Unauthorized: The endpoint is being accessed by a different user, the expected user is wazuh-server
 * - 500 Internal Server Error: Unexpected error during processing
 */
public class RestGetSubscriptionAction extends BaseRestHandler {
    private final ContentManagerService service;
    private static final String ENDPOINT_NAME = "content_manager_subscription_get";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_get";

    public RestGetSubscriptionAction(ContentManagerService service) {
        this.service = service;
    }

    @Override
    public String getName() { return ENDPOINT_NAME; }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(ContentManagerPlugin.SUBSCRIPTION_URI)
                        .method(GET)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build()
        );
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                Subscription subscription = service.getSubscription();
                if (subscription == null) {
                    ErrorResponse error = new ErrorResponse(
                            "Subscription not found",
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

                Token token = service.getToken();
                if (token == null) {
                    ErrorResponse error = new ErrorResponse(
                            "Token not found",
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

                XContentBuilder builder = XContentFactory.jsonBuilder();
                builder.startObject()
                        .field("access_token", token.getAccessToken())
                        .field("token_type", token.getTokenType())
                        .endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
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
}
