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
 * Transport request for content resource creation operations.
 *
 * <p>Carries the raw request body and content type information needed to create a new content
 * resource (Decoder, KVDB, Integration, Rule, or Filter).
 */
public class ContentCreateRequest extends ActionRequest {

    private final RestRequest.Method method;
    private final byte[] bodyContent;
    private final String contentType;

    /**
     * Constructs a new ContentCreateRequest.
     *
     * @param method the HTTP method of the original request
     * @param bodyContent the raw request body bytes
     * @param contentType the content type identifier ("json" or "yaml")
     */
    public ContentCreateRequest(RestRequest.Method method, byte[] bodyContent, String contentType) {
        super();
        this.method = method;
        this.bodyContent = bodyContent;
        this.contentType = contentType;
    }

    public ContentCreateRequest(StreamInput sin) throws IOException {
        super(sin);
        this.method = sin.readEnum(RestRequest.Method.class);
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
        out.writeByteArray(bodyContent);
        out.writeString(contentType);
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public byte[] getBodyContent() {
        return bodyContent;
    }

    public String getContentType() {
        return contentType;
    }
}
