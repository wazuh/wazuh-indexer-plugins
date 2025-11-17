package com.wazuh.contentmanager.rest;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.POST;

public class UpdateRestHandler extends BaseRestHandler {
    private final ContentManagerService service;

    public UpdateRestHandler(ContentManagerService service) {
        this.service = service;
    }

    @Override
    public String getName() { return "content_manager_update"; }

    @Override
    public List<Route> routes() {
        return List.of(
                // POST /_plugins/content-manager/update
                new NamedRoute.Builder()
                        .path("/_plugins/content-manager/update")
                        .method(POST)
                        .uniqueName("plugin:content_manager/update")
                        .build()
        );
    }
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {

        return channel -> {
            try {
                if (!service.canTriggerUpdate()) {
                    XContentBuilder b = XContentFactory.jsonBuilder();
                    b.startObject().field("error", "Too many update requests. Please try again later.").endObject();
                    BytesRestResponse resp = new BytesRestResponse(RestStatus.TOO_MANY_REQUESTS, b);
                    resp.addHeader("X-RateLimit-Limit", String.valueOf(10));
                    resp.addHeader("X-RateLimit-Remaining", String.valueOf(0));
                    resp.addHeader("X-RateLimit-Reset", String.valueOf(service.getRateLimitReset()));
                    channel.sendResponse(resp);
                    return;
                }

                XContentBuilder b = XContentFactory.jsonBuilder();
                BytesRestResponse resp = new BytesRestResponse(RestStatus.ACCEPTED, b);
                resp.addHeader("X-RateLimit-Limit", String.valueOf(10));
                resp.addHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, 10 - 1)));
                resp.addHeader("X-RateLimit-Reset", String.valueOf(service.getRateLimitReset()));
                channel.sendResponse(resp);
            } catch (Exception e) {
                XContentBuilder b = XContentFactory.jsonBuilder();
                b.startObject().field("error", "An unexpected error occurred while processing your request.").endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, b));
            }
        };
    }
}
