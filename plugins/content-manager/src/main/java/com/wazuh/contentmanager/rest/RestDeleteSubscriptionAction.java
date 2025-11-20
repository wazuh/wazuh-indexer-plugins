package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.model.rest.ErrorResponse;
import com.wazuh.contentmanager.model.rest.SubscriptionModel;
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

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/content-manager/subscription
 *
 * Deletes the current CTI subscription.
 *
 * Possible HTTP responses:
 * - 200 OK: Subscription successfully deleted
 * - 404 Not Found: No subscription exists to delete
 * - 401 Unauthorized: The endpoint is being accessed by a different user, the expected user is wazuh-dashboard
 * - 500 Internal Server Error: Unexpected error during processing
 */
public class RestDeleteSubscriptionAction extends BaseRestHandler {
    private final ContentManagerService service;

    public RestDeleteSubscriptionAction(ContentManagerService service) {
        this.service = service;
    }

    @Override
    public String getName() { return "content_manager_subscription_delete"; }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(ContentManagerPlugin.SUBSCRIPTION_URI)
                        .method(DELETE)
                        .uniqueName("plugin:content_manager/subscription_delete")
                        .build()
        );
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                SubscriptionModel subscription = service.getSubscription();
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
                service.deleteSubscription();
                
                XContentBuilder builder = XContentFactory.jsonBuilder();
                builder.startObject()
                        .field("status", RestStatus.OK.getStatus())
                        .field("message", "Subscription deleted successfully")
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
