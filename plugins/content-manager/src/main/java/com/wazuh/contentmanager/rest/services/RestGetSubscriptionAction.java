package com.wazuh.contentmanager.rest.services;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.rest.model.RestResponse;
import org.opensearch.transport.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/content-manager/subscription
 *
 * Retrieves the current CTI subscription token.
 *
 * Possible HTTP responses:
 * - 200 OK: Subscription found, returns access token and token type
 * - 404 Not Found: The token does not exist
 * - 401 Unauthorized: The endpoint is being accessed by a different user, the expected user is wazuh-server
 * - 500 Internal Server Error: Unexpected error during processing
 */
public class RestGetSubscriptionAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_subscription_get";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/subscription_get";
    private final CtiConsole ctiConsole;

    /**
     * Construct the REST handler.
     *
     * @param console the CTI console used to retrieve the token
     */
    public RestGetSubscriptionAction(CtiConsole console) {
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
     * @return the route configuration for this handler
     */
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

    /**
     * Prepare the request by returning a consumer that executes the lookup
     * and sends the appropriate response. Query parameters and request body
     * are ignored for this endpoint.
     *
     * @param request the incoming REST request
     * @param client the node client (unused)
     * @return a RestChannelConsumer that produces the response
     */
    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> {
            channel.sendResponse(this.handleRequest());
        };
    }

    /**
     * Execute the get-subscription operation.
     *
     * @return a BytesRestResponse containing the token information or error
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            Token token = this.ctiConsole.getToken();
            if (token == null) {
                RestResponse error = new RestResponse(
                    "Token not found",
                    RestStatus.NOT_FOUND.getStatus()
                );
                return new BytesRestResponse(RestStatus.NOT_FOUND, error.toXContent());
            }
            return new BytesRestResponse(RestStatus.OK, token.toXContent());
        } catch (Exception e) {
            RestResponse error = new RestResponse(
                e.getMessage() != null ? e.getMessage() : "An unexpected error occurred while processing your request.",
                RestStatus.INTERNAL_SERVER_ERROR.getStatus()
            );
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, error.toXContent());
        }
    }
}
