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
package com.wazuh.setup.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Response for an AI-assistant-session write: an HTTP status plus the body to render, verbatim.
 *
 * <p>The body is a map rather than a fixed set of fields because the four routes return three
 * different shapes. A successful {@code POST}/{@code PUT} returns the session itself, and a {@code
 * PATCH} the renamed session's identity — both a deliberate departure from this plugin's {@code
 * {message, status}} envelope, because the {@code version} token and the server-stamped {@code
 * updated_at} have to reach the client on the write itself: without {@code version} the next {@code
 * PUT} conflicts, and a chat client cannot afford an extra read per turn. {@code DELETE}, having
 * nothing to round-trip, keeps the envelope, as do the {@code 400} and {@code 409} outcomes.
 */
public class PutAiAssistantSessionResponse extends ActionResponse implements ToXContent {
    private static final String MESSAGE = "message";
    private static final String STATUS = "status";
    private static final String ID = "id";

    private final RestStatus status;
    private final Map<String, Object> body;

    /**
     * Constructs a new response.
     *
     * @param status the HTTP status, also passed to the REST layer to set the response code.
     * @param body the response body, rendered as-is.
     */
    public PutAiAssistantSessionResponse(RestStatus status, Map<String, Object> body) {
        super();
        this.status = status;
        this.body = body;
    }

    /**
     * Builds the {@code {message, status}} envelope this plugin uses for outcomes that carry no
     * resource — the {@code 400}s, the {@code 409}s and {@code DELETE}.
     *
     * @param message the outcome message; sentence-case with a trailing period.
     * @param status the HTTP status.
     * @param id the affected session id, or {@code null} when there is none.
     * @return the response.
     */
    public static PutAiAssistantSessionResponse envelope(
            String message, RestStatus status, String id) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put(MESSAGE, message);
        body.put(STATUS, status.getStatus());
        if (id != null) {
            body.put(ID, id);
        }
        return new PutAiAssistantSessionResponse(status, body);
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    @SuppressWarnings("unchecked")
    public PutAiAssistantSessionResponse(StreamInput sin) throws IOException {
        this(sin.readEnum(RestStatus.class), (Map<String, Object>) sin.readGenericValue());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(this.status);
        out.writeGenericValue(this.body);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.map(this.body);
    }

    public RestStatus getStatus() {
        return this.status;
    }

    public Map<String, Object> getBody() {
        return this.body;
    }
}
