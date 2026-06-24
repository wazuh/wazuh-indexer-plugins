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

import java.io.IOException;

/**
 * Transport request for content resource delete operations.
 *
 * <p>Carries the resource ID needed to delete an existing content resource.
 */
public class ContentDeleteRequest extends ActionRequest {

    private final RestRequest.Method method;
    private final String id;

    public ContentDeleteRequest(RestRequest.Method method, String id) {
        super();
        this.method = method;
        this.id = id;
    }

    public ContentDeleteRequest(StreamInput sin) throws IOException {
        super(sin);
        this.method = sin.readEnum(RestRequest.Method.class);
        this.id = sin.readString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeEnum(method);
        out.writeString(id);
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public String getId() {
        return id;
    }
}
