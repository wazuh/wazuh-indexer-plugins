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

    public RestGetSubscriptionAction(CtiConsole console) {
        this.ctiConsole = console;
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
                Token token = this.ctiConsole.getToken();
                if (token == null) {
                    RestResponse error = new RestResponse(
                            "Token not found",
                            RestStatus.NOT_FOUND.getStatus()
                    );
                    channel.sendResponse(new BytesRestResponse(RestStatus.NOT_FOUND, error.toXContent()));
                    return;
                }
                channel.sendResponse(new BytesRestResponse(RestStatus.OK, token.toXContent()));
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
