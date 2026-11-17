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
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import com.wazuh.contentmanager.action.DeleteSubscriptionAction;
import com.wazuh.contentmanager.action.DeleteSubscriptionRequest;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/_content_manager/subscription
 *
 * <p>Removes stored CTI credentials by delegating to the transport action {@link
 * DeleteSubscriptionAction}, which calls {@link
 * com.wazuh.contentmanager.cti.catalog.service.SubscriptionService#unregister}.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Credentials removed successfully.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 *
 * <p>With {@code ?perform_permission_check=true} the endpoint answers "may the current user delete
 * the subscription?" instead of deleting it. The stored token is never removed in this mode: the
 * security plugin's action filter answers before {@code TransportDeleteSubscriptionAction}
 * executes, and with security disabled the transport action recognizes the request and answers
 * without unregistering. The response is always {@code 200}, and the caller must branch on the
 * {@code accessAllowed} field rather than on the status:
 *
 * <ul>
 *   <li>{@code {"accessAllowed": true, "missingPrivileges": []}}
 *   <li>{@code {"accessAllowed": false, "missingPrivileges":
 *       ["cluster:admin/content_manager/subscription/delete"]}}
 * </ul>
 *
 * @see PermissionCheckSupport
 */
public class RestDeleteSubscriptionAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestDeleteSubscriptionAction.class);
    private static final String ENDPOINT_NAME = "content_manager_subscription_delete";

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the DELETE endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(DELETE, PluginSettings.SUBSCRIPTION_URI));
    }

    /**
     * Delegates to the transport action via {@link DeleteSubscriptionAction}. In permission-check
     * mode the request is flagged so that it never unregisters.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that sends the credential removal response
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug("{} {}", request.method(), PluginSettings.SUBSCRIPTION_URI);

        boolean permissionCheckOnly = PermissionCheckSupport.isPermissionCheck(request);

        // The dispatch is the same in both modes, so the security filter evaluates exactly the
        // permission a real deletion needs.
        DeleteSubscriptionRequest subscriptionRequest =
                permissionCheckOnly
                        ? DeleteSubscriptionRequest.permissionCheck()
                        : new DeleteSubscriptionRequest();

        return channel ->
                PermissionCheckSupport.execute(
                        client,
                        DeleteSubscriptionAction.INSTANCE,
                        subscriptionRequest,
                        channel,
                        permissionCheckOnly);
    }
}
