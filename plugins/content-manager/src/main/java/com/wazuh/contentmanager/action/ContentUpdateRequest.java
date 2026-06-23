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
 * Transport request for content resource update operations.
 *
 * <p>Carries the resource ID, raw request body, and content type information needed to update an
 * existing content resource.
 */
public class ContentUpdateRequest extends ActionRequest {

    private final RestRequest.Method method;
    private final String id;
    private final byte[] bodyContent;
    private final String contentType;

    public ContentUpdateRequest(
            RestRequest.Method method, String id, byte[] bodyContent, String contentType) {
        super();
        this.method = method;
        this.id = id;
        this.bodyContent = bodyContent;
        this.contentType = contentType;
    }

    public ContentUpdateRequest(StreamInput sin) throws IOException {
        super(sin);
        this.method = sin.readEnum(RestRequest.Method.class);
        this.id = sin.readString();
        this.bodyContent = sin.readByteArray();
        this.contentType = sin.readString();
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
        out.writeByteArray(bodyContent);
        out.writeString(contentType);
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public String getId() {
        return id;
    }

    public byte[] getBodyContent() {
        return bodyContent;
    }

    public String getContentType() {
        return contentType;
    }
}
