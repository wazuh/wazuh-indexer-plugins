package com.wazuh.contentmanager.rest.services;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Subscription;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.model.SubscriptionParser;
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
 * POST /_plugins/content-manager/subscription
 *
 * Creates or updates the CTI subscription.
 *
 * Possible HTTP responses:
 * - 201 Created: Subscription successfully created or updated
 * - 400 Bad Request: Missing required parameters (device_code, client_id, expires_in, interval)
 * - 401 Unauthorized: The endpoint is being accessed by a different user, the expected user is wazuh-dashboard
 * - 500 Internal Server Error: Unexpected error during processing
 */
public class RestPostSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_post";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_post";
    private final CtiConsole ctiConsole;

    public RestPostSubscriptionAction(CtiConsole console) {
        this.ctiConsole = console;
    }

    @Override
    public String getName() { return ENDPOINT_NAME; }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(ContentManagerPlugin.SUBSCRIPTION_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build()
        );
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                // Parse subscription details and create a new instance of Subscription DTO.
                Subscription subscription = SubscriptionParser.parse(request.contentParser());

                // Notify CTI Console about a registration request
                this.ctiConsole.onPostSubscriptionRequest(subscription);

                // Return success
                RestResponse response = new RestResponse("Subscription created successfully", RestStatus.CREATED.getStatus());
                channel.sendResponse(new BytesRestResponse(RestStatus.CREATED, response.toXContent()));
            } catch (IllegalArgumentException e) {
                RestResponse error = new RestResponse(
                    e.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus()
                );
                channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, error.toXContent()));
            }
            catch (Exception e) {
                RestResponse error = new RestResponse(
                        e.getMessage() != null ? e.getMessage() : "An unexpected error occurred while processing your request.",
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus()
                );
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent()));
            }
        };
    }
}
