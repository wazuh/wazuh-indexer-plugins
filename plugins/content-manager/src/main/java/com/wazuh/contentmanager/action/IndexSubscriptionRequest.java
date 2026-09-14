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
package com.wazuh.contentmanager.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

import static org.opensearch.action.ValidateActions.addValidationError;

/**
 * Request for {@link IndexSubscriptionAction}.
 *
 * <p>Two shapes, distinguished by {@link #isPermissionCheckOnly()}:
 *
 * <ul>
 *   <li>a real registration, carrying the CTI {@code access_token};
 *   <li>a permission check, carrying no token, built with {@link #permissionCheck()}. It exists
 *       only so the request reaches the security plugin's action filter, which answers it instead
 *       of letting the action execute.
 * </ul>
 */
public class IndexSubscriptionRequest extends ActionRequest {

    public static final String ACCESS_TOKEN_IS_MISSING = "Access token is missing";
    private static final String ACCESS_TOKEN_FIELD = "access_token";
    private final String token;
    private final boolean permissionCheckOnly;

    /**
     * Builds a registration request.
     *
     * @param token the CTI access token
     */
    public IndexSubscriptionRequest(String token) {
        this(token, false);
    }

    private IndexSubscriptionRequest(String token, boolean permissionCheckOnly) {
        super();
        this.token = token;
        this.permissionCheckOnly = permissionCheckOnly;
    }

    /**
     * Builds a request that only exercises the authorization filter. It carries no access token and
     * must never perform registration work.
     *
     * @return a permission-check-only request
     */
    public static IndexSubscriptionRequest permissionCheck() {
        return new IndexSubscriptionRequest(null, true);
    }

    /**
     * Deserializing constructor.
     *
     * @param sin the stream to read from
     * @throws IOException on read failure
     */
    public IndexSubscriptionRequest(StreamInput sin) throws IOException {
        super(sin);
        this.token = sin.readOptionalString();
        this.permissionCheckOnly = sin.readBoolean();
    }

    /**
     * Validates the request.
     *
     * <p>The access token check is skipped for a permission check, and that is load-bearing rather
     * than a convenience: {@code TransportAction.execute} runs validation <em>before</em> the {@code
     * ActionFilters} chain, so a blank token would be answered {@code 400} and the security filter
     * would never get to evaluate the request.
     *
     * @return the validation error, or {@code null} when the request is valid
     */
    @Override
    public ActionRequestValidationException validate() {
        if (this.permissionCheckOnly) {
            return null;
        }

        ActionRequestValidationException validationException = null;

        if (this.token == null || this.token.isBlank()) {
            validationException =
                    addValidationError("Missing [" + ACCESS_TOKEN_FIELD + "] field.", validationException);
        }

        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(token);
        out.writeBoolean(permissionCheckOnly);
    }

    public String getToken() {
        return token;
    }

    /**
     * @return true when this request must not perform any registration work
     */
    public boolean isPermissionCheckOnly() {
        return permissionCheckOnly;
    }
}
