/*
 * Copyright (C) 2024-2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager.rest.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.StatusToXContentObject;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.action.IndexSubscriptionAction;
import com.wazuh.contentmanager.action.IndexSubscriptionRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/_content_manager/subscription
 *
 * <p>Parses the {@code access_token} field from the JSON body and delegates to the transport
 * action, which calls {@link
 * com.wazuh.contentmanager.cti.catalog.service.SubscriptionService#register}.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: Credentials stored successfully.
 *   <li>400 Bad Request: Missing or empty access_token field.
 *   <li>412 Precondition Failed: Credentials index is not a system index.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 *
 * <p>With {@code ?perform_permission_check=true} the endpoint answers "may the current user
 * register a subscription?" instead of registering one. No body is read, no access token is
 * required and the request has no side effects: the security plugin's action filter answers it
 * before {@code TransportIndexSubscriptionAction} executes. The response is always {@code 200}, and
 * the caller must branch on the {@code accessAllowed} field rather than on the status:
 *
 * <ul>
 *   <li>{@code {"accessAllowed": true, "missingPrivileges": []}}
 *   <li>{@code {"accessAllowed": false, "missingPrivileges":
 *       ["cluster:admin/content_manager/subscription/create"]}}
 * </ul>
 */
public class RestPostSubscriptionAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostSubscriptionAction.class);
    private static final String ENDPOINT_NAME = "content_manager_subscription_post";
    private static final String ACCESS_TOKEN_FIELD = "access_token";

    /**
     * Owned by the security plugin: {@code ConfigConstants.SECURITY_PERFORM_PERMISSION_CHECK_PARAM}.
     * {@code SecurityRestFilter} has already consumed it by the time this handler runs — which is
     * also what stops {@link BaseRestHandler} from rejecting it as unrecognized — but the handler
     * reads it again so it stays self-contained.
     */
    private static final String PERFORM_PERMISSION_CHECK_PARAM = "perform_permission_check";

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the POST endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, PluginSettings.SUBSCRIPTION_URI));
    }

    /**
     * Parses the {@code access_token} field from the request body and delegates to the transport
     * action via {@link IndexSubscriptionAction}. In permission-check mode no body is parsed.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the subscription registration response
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {

        log.debug("{} {}", request.method(), PluginSettings.SUBSCRIPTION_URI);

        boolean permissionCheckOnly = request.paramAsBoolean(PERFORM_PERMISSION_CHECK_PARAM, false);

        // Check-only mode: no body is parsed, no access token is read. The dispatch is otherwise
        // unchanged, so the security filter evaluates exactly the permission a real registration
        // would need.
        IndexSubscriptionRequest subscriptionRequest =
                permissionCheckOnly
                        ? IndexSubscriptionRequest.permissionCheck()
                        : new IndexSubscriptionRequest(parseAccessToken(request));

        return channel -> execute(client, subscriptionRequest, channel, permissionCheckOnly);
    }

    private String parseAccessToken(RestRequest request) throws IOException {
        String accessToken = null;
        try (XContentParser parser = request.contentParser()) {
            XContentParser.Token token;
            while ((token = parser.nextToken()) != null) {
                if (token == XContentParser.Token.FIELD_NAME
                        && ACCESS_TOKEN_FIELD.equals(parser.currentName())) {
                    parser.nextToken();
                    accessToken = parser.text();
                } else if (token == XContentParser.Token.END_OBJECT) {
                    break;
                }
            }
        }
        return accessToken;
    }

    /**
     * Dispatches the request with a listener typed over {@link ActionResponse}.
     *
     * <p>The raw cast is deliberate and mirrors what the security plugin already does on its side:
     * {@code SecurityFilter} hands its own {@code PermissionCheckResponse} to this listener through
     * an unchecked cast. A listener declared over the concrete {@link MessageStatusResponse} would
     * generate a bridge method casting to that class and throw {@code ClassCastException}, which
     * {@code RestActionListener} turns into a {@code 500}. Declaring it over {@code ActionResponse} —
     * the common supertype of both responses — makes the bridge cast succeed.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void execute(
            NodeClient client,
            IndexSubscriptionRequest subscriptionRequest,
            RestChannel channel,
            boolean permissionCheckOnly) {
        client.execute(
                IndexSubscriptionAction.INSTANCE,
                subscriptionRequest,
                (ActionListener) createSubscriptionResponse(channel, permissionCheckOnly));
    }

    private RestResponseListener<ActionResponse> createSubscriptionResponse(
            RestChannel channel, boolean permissionCheckOnly) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(ActionResponse response) throws Exception {
                // The security plugin answered the permission check. Pass its body through
                // unchanged so this endpoint is indistinguishable from any other in the cluster.
                if (response instanceof StatusToXContentObject permissionCheck) {
                    return new BytesRestResponse(
                            permissionCheck.status(),
                            permissionCheck.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
                }

                // No filter intercepted a check-mode request: security is disabled, so the answer
                // is "allowed". Same field names, so a client cannot tell the two producers apart.
                if (permissionCheckOnly) {
                    return permissionGrantedResponse();
                }

                MessageStatusResponse subscriptionResponse = (MessageStatusResponse) response;
                return new BytesRestResponse(
                        subscriptionResponse.getStatus(),
                        subscriptionResponse.toXContent(
                                XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }

    /** Builds the security-disabled fallback body, matching {@code PermissionCheckResponse}. */
    private static RestResponse permissionGrantedResponse() throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder
                .startObject()
                .field(Constants.KEY_ACCESS_ALLOWED, true)
                .startArray(Constants.KEY_MISSING_PRIVILEGES)
                .endArray()
                .endObject();
        return new BytesRestResponse(RestStatus.OK, builder);
    }
}
