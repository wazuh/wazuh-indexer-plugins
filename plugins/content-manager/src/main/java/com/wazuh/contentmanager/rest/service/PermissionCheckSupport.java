/*
 * Copyright (C) 2026, Wazuh Inc.
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

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.common.xcontent.StatusToXContentObject;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Support for the security plugin's {@code perform_permission_check} parameter on endpoints whose
 * transport action answers a {@link MessageStatusResponse}.
 *
 * <p>With the parameter set, the endpoint checks whether the current user is allowed to run its
 * request, without running it. The answer is always a {@code 200} carrying {@code accessAllowed}
 * and {@code missingPrivileges}; a user who is not allowed gets {@code accessAllowed: false}, not a
 * {@code 403}. Who produces it depends on the security plugin:
 *
 * <ul>
 *   <li>Enabled: its action filter evaluates the same permission the real request needs and answers
 *       with its own {@code PermissionCheckResponse}, so the transport action never executes.
 *   <li>Disabled: no filter intercepts the request, so the transport action must recognize a
 *       check-only request and answer it without doing any work. Every caller is allowed.
 * </ul>
 *
 * <p>{@link #execute} renders whichever of the two responses comes back.
 */
final class PermissionCheckSupport {

    /**
     * Owned by the security plugin: {@code ConfigConstants.SECURITY_PERFORM_PERMISSION_CHECK_PARAM}.
     * {@code SecurityRestFilter} has already consumed it by the time a handler runs, which is also
     * what stops {@code BaseRestHandler} from rejecting it as unrecognized. With security disabled
     * nothing else reads it, so {@link #isPermissionCheck} must.
     */
    static final String PERFORM_PERMISSION_CHECK_PARAM = "perform_permission_check";

    private PermissionCheckSupport() {}

    /**
     * Reads the {@code perform_permission_check} parameter. An empty value means {@code true}.
     *
     * @param request the incoming REST request
     * @return whether the caller asks for the authorization decision instead of the operation
     */
    static boolean isPermissionCheck(RestRequest request) {
        return request.paramAsBoolean(PERFORM_PERMISSION_CHECK_PARAM, false);
    }

    /**
     * Dispatches the request and renders the response.
     *
     * <p>The listener is typed over {@link ActionResponse} and passed through a raw cast. That
     * mirrors what the security plugin already does on its side: {@code SecurityFilter} hands its own
     * {@code PermissionCheckResponse} to this listener through an unchecked cast. A listener declared
     * over the concrete {@link MessageStatusResponse} would generate a bridge method casting to that
     * class and throw {@code ClassCastException}, which {@code RestActionListener} turns into a
     * {@code 500}. Declaring it over {@code ActionResponse}, the common supertype of both responses,
     * makes the bridge cast succeed.
     *
     * @param client the node client
     * @param action the transport action to run
     * @param request the request, flagged as check-only when {@code permissionCheckOnly} is set
     * @param channel the channel to answer on
     * @param permissionCheckOnly whether the caller asked for the authorization decision only
     */
    @SuppressWarnings("unchecked")
    static void execute(
            NodeClient client,
            ActionType<MessageStatusResponse> action,
            ActionRequest request,
            RestChannel channel,
            boolean permissionCheckOnly) {
        client.execute(
                action,
                request,
                (ActionListener) PermissionCheckSupport.responseListener(channel, permissionCheckOnly));
    }

    private static RestResponseListener<ActionResponse> responseListener(
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
                    return PermissionCheckSupport.permissionGrantedResponse();
                }

                MessageStatusResponse messageResponse = (MessageStatusResponse) response;
                return new BytesRestResponse(
                        messageResponse.getStatus(),
                        messageResponse.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
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
