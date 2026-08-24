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

/** Response for an AI-assistant-settings write, carrying the outcome message and HTTP status. */
public class PutAiAssistantSettingsResponse extends ActionResponse implements ToXContent {
    private static final String MESSAGE = "message";
    private static final String STATUS = "status";
    private static final String ID = "id";

    private final String message;
    private final RestStatus status;
    private final String id;

    /**
     * Constructs a new response.
     *
     * @param message the outcome message.
     * @param status the HTTP status.
     * @param id the affected provider document id, or {@code null} when not applicable.
     */
    public PutAiAssistantSettingsResponse(String message, RestStatus status, String id) {
        super();
        this.message = message;
        this.status = status;
        this.id = id;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public PutAiAssistantSettingsResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readEnum(RestStatus.class), sin.readOptionalString());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.message);
        out.writeEnum(this.status);
        out.writeOptionalString(this.id);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field(MESSAGE, this.message).field(STATUS, this.status.getStatus());
        if (this.id != null) {
            builder.field(ID, this.id);
        }
        return builder.endObject();
    }

    public String getMessage() {
        return this.message;
    }

    public RestStatus getStatus() {
        return this.status;
    }

    public String getId() {
        return this.id;
    }
}
