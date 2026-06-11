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
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;

import java.io.IOException;

import static org.opensearch.action.ValidateActions.addValidationError;

public class CreateSubscriptionRequest extends ActionRequest {

    public static final String ACCESS_TOKEN_IS_MISSING = "Access token is missing";
    private static final String ACCESS_TOKEN_FIELD = "access_token";
    private final RestRequest.Method method;
    private final String token;

    public CreateSubscriptionRequest(Method method, String token) {
        super();
        this.method = method;
        this.token = token;
    }

    public CreateSubscriptionRequest(StreamInput sin) throws IOException {
        this(sin.readEnum(Method.class), sin.readString());
    }

    @Override
    public ActionRequestValidationException validate() {
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
        out.writeEnum(method);
        out.writeString(token);
    }

    public String getToken() {
        return token;
    }

    public Method getMethod() {
        return method;
    }
}
