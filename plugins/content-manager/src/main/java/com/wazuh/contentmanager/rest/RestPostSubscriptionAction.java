package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.model.rest.Credentials;
import com.wazuh.contentmanager.model.rest.ErrorResponse;
import com.wazuh.contentmanager.model.rest.SubscriptionModel;
import com.wazuh.contentmanager.services.ContentManagerService;
import org.opensearch.transport.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;

import java.util.ArrayList;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/content-manager/subscription
 *
 * Creates or updates the CTI subscription (singleton).
 *
 * Possible HTTP responses:
 * - 201 Created: Subscription successfully created or updated
 * - 400 Bad Request: Missing required parameters (device_code, client_id, expires_in, interval)
 * - 401 Unauthorized: The endpoint is being accessed by a different user, the expected user is wazuh-dashboard
 * - 500 Internal Server Error: Unexpected error during processing
 */
public class RestPostSubscriptionAction extends BaseRestHandler {
    private final ContentManagerService service;

    public RestPostSubscriptionAction(ContentManagerService service) {
        this.service = service;
    }

    @Override
    public String getName() { return "content_manager_subscription_post"; }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(ContentManagerPlugin.SUBSCRIPTION_URI)
                        .method(POST)
                        .uniqueName("plugin:content_manager/subscription_post")
                        .build()
        );
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                XContentParser parser = request.contentParser();
                String deviceCode = null, clientId = null;
                Integer expiresIn = null, interval = null;
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

                List<String> missing = new ArrayList<>();
                if (deviceCode == null) missing.add("device_code");
                if (clientId == null) missing.add("client_id");
                if (expiresIn == null) missing.add("expires_in");
                if (interval == null) missing.add("interval");

                if (!missing.isEmpty()) {
                    ErrorResponse error = new ErrorResponse(
                            "Required parameters missing: " + String.join(", ", missing),
                            RestStatus.BAD_REQUEST.getStatus()
                    );
                    XContentBuilder builder = XContentFactory.jsonBuilder();
                    builder.startObject()
                            .field("message", error.getMessage())
                            .field("status", error.getStatus())
                            .endObject();
                    channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, builder));
                    return;
                }

                // Create or update the subscription using the singleton pattern
                SubscriptionModel.createOrUpdate(deviceCode, clientId, expiresIn, interval);
                
                // TODO: This is a temporary placeholder. Replace with actual credentials from authentication flow.
                Credentials.createOrUpdate("temporary_access_token", "Bearer");
                
                XContentBuilder builder = XContentFactory.jsonBuilder();
                builder.startObject()
                        .field("status", RestStatus.CREATED.getStatus())
                        .field("message", "Subscription created successfully")
                        .endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.CREATED, builder));
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
