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

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Response for {@link GetPolicyResourcesAction}.
 *
 * <p>On success it carries the ids of the space's resources grouped by pipeline phase: {@code
 * normalization} (decoders, filters and kvdbs) and {@code detection} (rules). On a validation
 * failure it carries a message and the status, like the other Content Manager endpoints.
 */
public class GetPolicyResourcesResponse extends ActionResponse implements ToXContent {
    private final String message;
    private final RestStatus status;
    private final List<String> decoders;
    private final List<String> filters;
    private final List<String> kvdbs;
    private final List<String> rules;

    /**
     * Error / simple-message constructor.
     *
     * @param message The error message.
     * @param status The HTTP status.
     */
    public GetPolicyResourcesResponse(String message, RestStatus status) {
        super();
        this.message = message;
        this.status = status;
        this.decoders = null;
        this.filters = null;
        this.kvdbs = null;
        this.rules = null;
    }

    /**
     * Success constructor carrying the space's resource ids.
     *
     * @param decoders The decoder ids.
     * @param filters The filter ids.
     * @param kvdbs The kvdb ids.
     * @param rules The rule ids.
     */
    public GetPolicyResourcesResponse(
            List<String> decoders, List<String> filters, List<String> kvdbs, List<String> rules) {
        super();
        this.message = null;
        this.status = RestStatus.OK;
        this.decoders = decoders;
        this.filters = filters;
        this.kvdbs = kvdbs;
        this.rules = rules;
    }

    /**
     * Stream constructor.
     *
     * @param sin The stream input.
     * @throws IOException If reading fails.
     */
    public GetPolicyResourcesResponse(StreamInput sin) throws IOException {
        super(sin);
        this.status = sin.readEnum(RestStatus.class);
        this.message = sin.readOptionalString();
        if (sin.readBoolean()) {
            this.decoders = sin.readStringList();
            this.filters = sin.readStringList();
            this.kvdbs = sin.readStringList();
            this.rules = sin.readStringList();
        } else {
            this.decoders = null;
            this.filters = null;
            this.kvdbs = null;
            this.rules = null;
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(status);
        out.writeOptionalString(message);
        if (message == null) {
            out.writeBoolean(true);
            out.writeStringCollection(decoders);
            out.writeStringCollection(filters);
            out.writeStringCollection(kvdbs);
            out.writeStringCollection(rules);
        } else {
            out.writeBoolean(false);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (message == null) {
            builder.startObject(Constants.KEY_NORMALIZATION);
            builder.field(Constants.KEY_DECODERS, decoders);
            builder.field(Constants.KEY_FILTERS, filters);
            builder.field(Constants.KEY_KVDBS, kvdbs);
            builder.endObject();
            builder.startObject(Constants.KEY_DETECTION);
            builder.field(Constants.KEY_RULES, rules);
            builder.endObject();
        } else {
            builder.field(Constants.KEY_MESSAGE, message);
        }
        builder.field(Constants.KEY_STATUS, status.getStatus());
        return builder.endObject();
    }

    /**
     * Returns the response message, or {@code null} on success.
     *
     * @return The message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Returns the response status.
     *
     * @return The status.
     */
    public RestStatus getStatus() {
        return status;
    }
}
