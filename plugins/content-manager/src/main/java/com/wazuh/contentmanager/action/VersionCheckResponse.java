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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Map;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport-layer response for the version check endpoint. Supports two modes: a structured
 * version-check payload (message rendered as JSON object) or a simple error string.
 */
public class VersionCheckResponse extends ActionResponse implements ToXContent {
    private final String message;
    private final RestStatus status;
    private Object parsedMessage;

    /** Simple string message constructor (errors). */
    public VersionCheckResponse(String message, RestStatus status) {
        super();
        this.message = message;
        this.status = status;
    }

    /** Constructor with parsed message object (success payloads). */
    public VersionCheckResponse(String message, RestStatus status, Object parsedMessage) {
        super();
        this.message = message;
        this.status = status;
        this.parsedMessage = parsedMessage;
    }

    public VersionCheckResponse(StreamInput sin) throws IOException {
        super();
        this.message = sin.readString();
        this.status = sin.readEnum(RestStatus.class);
        if (sin.readBoolean()) {
            this.parsedMessage = sin.readGenericValue();
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(message);
        out.writeEnum(status);
        if (parsedMessage != null) {
            out.writeBoolean(true);
            out.writeGenericValue(parsedMessage);
        } else {
            out.writeBoolean(false);
        }
    }

    /**
     * Attempts to parse the message string as JSON. If successful, the parsed structure will be used
     * in {@link #toXContent} instead of the raw string.
     *
     * @return this instance for chaining
     */
    public VersionCheckResponse parseMessageAsJson() {
        if (this.message != null && !this.message.isBlank()) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode node = mapper.readTree(this.message);
                if (node.isObject()) {
                    this.parsedMessage = mapper.convertValue(node, Map.class);
                } else if (node.isArray()) {
                    this.parsedMessage = mapper.convertValue(node, java.util.List.class);
                }
            } catch (Exception e) {
                // fall back to string
            }
        }
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (parsedMessage != null) {
            builder.field(Constants.KEY_MESSAGE, parsedMessage);
        } else {
            builder.field(Constants.KEY_MESSAGE, message);
        }
        builder.field(Constants.KEY_STATUS, status.getStatus());
        return builder.endObject();
    }

    public String getMessage() {
        return message;
    }

    public RestStatus getStatus() {
        return status;
    }
}
