package com.wazuh.contentmanager.rest.services;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Subscription;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.model.SubscriptionParser;
import org.opensearch.transport.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
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

    /**
     * Construct the REST handler.
     *
     * @param console the CTI console used to handle subscription requests
     */
    public RestPostSubscriptionAction(CtiConsole console) {
        this.ctiConsole = console;
    }

    /**
     * Return a short name identifying this handler.
     *
     * @return a short name identifying this handler
     */
    @Override
    public String getName() { return ENDPOINT_NAME; }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for POST subscription
     */
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

    /**
     * Prepare the request by parsing the incoming subscription payload and
     * returning a consumer that forwards the parsed DTO to {@link #handleRequest}.
     *
     * @param request the incoming REST request containing the subscription payload
     * @param client the node client (unused)
     * @return a RestChannelConsumer that processes the request and sends the response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            // Parse subscription details and create a new instance of Subscription DTO.
            Subscription subscription = SubscriptionParser.parse(request.contentParser());

            // Send response from handleRequest method which process the request.
            channel.sendResponse(this.handleRequest(subscription));
        };
    }

    /**
     * Handle the subscription creation/update.
     *
     *
     * @param subscription the parsed subscription DTO
     * @return a BytesRestResponse representing the operation result
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest(Subscription subscription) throws IOException {
        try {
            // Notify CTI Console about a registration request
            this.ctiConsole.onPostSubscriptionRequest(subscription);

            // Return success
            RestResponse response = new RestResponse("Subscription created successfully", RestStatus.CREATED.getStatus());
            return new BytesRestResponse(RestStatus.CREATED, response.toXContent());
        } catch (IllegalArgumentException e) {
            RestResponse error = new RestResponse(
                e.getMessage(),
                RestStatus.BAD_REQUEST.getStatus()
            );
            return new BytesRestResponse(RestStatus.BAD_REQUEST, error.toXContent());
        }
        catch (Exception e) {
            RestResponse error = new RestResponse(
                e.getMessage() != null ? e.getMessage() : "An unexpected error occurred while processing your request.",
                RestStatus.INTERNAL_SERVER_ERROR.getStatus()
            );
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent());
        }
    }
}
