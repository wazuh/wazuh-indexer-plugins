package com.wazuh.contentmanager.rest;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.*;

/**
 * Handles /subscription endpoints: POST, GET, DELETE
 */
public class SubscriptionRestHandler extends BaseRestHandler {
    private final ContentManagerService service;

    public SubscriptionRestHandler(ContentManagerService service) {
        this.service = service;
    }

    @Override
    public String getName() { return "content_manager_subscription"; }

    @Override
    public List<Route> routes() {
        return List.of(
                // POST /_plugins/content-manager/subscription
                new NamedRoute.Builder()
                        .path("/_plugins/content-manager/subscription")
                        .method(POST)
                        .uniqueName("plugin:content_manager/subscription_post")
                        .build(),

                // GET /_plugins/content-manager/subscription
                new NamedRoute.Builder()
                        .path("/_plugins/content-manager/subscription")
                        .method(GET)
                        .uniqueName("plugin:content_manager/subscription_get")
                        .build(),

                // DELETE /_plugins/content-manager/subscription
                new NamedRoute.Builder()
                        .path("/_plugins/content-manager/subscription")
                        .method(DELETE)
                        .uniqueName("plugin:content_manager/subscription_delete")
                        .build()
        );
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {

        return channel -> {
            try {
                if (request.method() == POST) {
                    XContentParser parser = request.contentParser();
                    String deviceCode = null, clientId = null;
                    int expiresIn = 0, interval = 0;
                    while (!parser.isClosed()) {
                        XContentParser.Token token = parser.nextToken();
                        if (token == null) break;
                        if (token.isValue()) {
                            String fieldName = parser.currentName();
                            if ("device_code".equals(fieldName)) deviceCode = parser.text();
                            else if ("client_id".equals(fieldName)) clientId = parser.text();
                            else if ("expires_in".equals(fieldName)) expiresIn = parser.intValue();
                            else if ("interval".equals(fieldName)) interval = parser.intValue();
                        }
                    }
                    if (deviceCode == null || clientId == null) {
                        XContentBuilder b = XContentFactory.jsonBuilder();
                        b.startObject().field("error", "Required parameter 'client_id' is missing.").endObject();
                        channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, b));
                        return;
                    }
                    ContentManagerService.Subscription s = new ContentManagerService.Subscription(deviceCode, clientId, expiresIn, interval);
                    service.saveSubscription(s);
                    channel.sendResponse(new BytesRestResponse(RestStatus.CREATED, ""));
                } else if (request.method() == GET) {
                    ContentManagerService.Subscription s = service.getSubscription();
                    if (s == null) {
                        channel.sendResponse(new BytesRestResponse(RestStatus.NOT_FOUND, ""));
                        return;
                    }
                    XContentBuilder b = XContentFactory.jsonBuilder();
                    b.startObject().field("access_token", "mock-token").field("token_type", "Bearer").endObject();
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, b));
                } else if (request.method() == RestRequest.Method.DELETE) {
                    ContentManagerService.Subscription s = service.getSubscription();
                    if (s == null) {
                        channel.sendResponse(new BytesRestResponse(RestStatus.NOT_FOUND, ""));
                        return;
                    }
                    service.deleteSubscription();
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, ""));
                } else {
                    channel.sendResponse(new BytesRestResponse(RestStatus.METHOD_NOT_ALLOWED, ""));
                }
            } catch (Exception e) {
                XContentBuilder b = XContentFactory.jsonBuilder();
                b.startObject().field("error", "An unexpected error occurred while processing your request.").endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, b));
            }
        };
    }
}
