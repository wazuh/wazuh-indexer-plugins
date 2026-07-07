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

import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport response for logtest endpoints. Supports serializing the message field as structured
 * JSON when the message string is valid JSON, mirroring the behavior of {@code
 * RestResponse.parseMessageAsJson()}.
 */
public class LogtestResponse extends ActionResponse implements ToXContent {
    private final String message;
    private final RestStatus status;
    private transient Object parsedMessage;

    public LogtestResponse(String message, RestStatus status) {
        super();
        this.message = message;
        this.status = status;
        this.parsedMessage = tryParseMessageAsJson(message);
    }

    public LogtestResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readEnum(RestStatus.class));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(message);
        out.writeEnum(status);
    }

    /**
     * Attempts to parse the message string as JSON. If successful, returns a Map or List that
     * XContentBuilder can serialize as structured JSON rather than a plain string.
     */
    private static Object tryParseMessageAsJson(String message) {
        if (message != null && !message.isBlank()) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode node = mapper.readTree(message);
                if (node.isObject()) {
                    return mapper.convertValue(node, java.util.Map.class);
                } else if (node.isArray()) {
                    return mapper.convertValue(node, java.util.List.class);
                }
            } catch (Exception e) {
                // Fall back to string representation
            }
        }
        return null;
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
        builder.endObject();
        return builder;
    }

    public String getMessage() {
        return message;
    }

    public RestStatus getStatus() {
        return status;
    }
}
