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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Response for GET /promote. Can carry either a structured {@code changes} map (success) or a
 * simple {@code message} + {@code status} error payload.
 */
public class GetPromoteResponse extends ActionResponse implements ToXContent {
    private final String message;
    private final RestStatus status;
    private final Map<String, List<Map<String, String>>> changes;

    /** Error / simple-message constructor. */
    public GetPromoteResponse(String message, RestStatus status) {
        super();
        this.message = message;
        this.status = status;
        this.changes = null;
    }

    /** Success constructor carrying the changes map. */
    public GetPromoteResponse(Map<String, List<Map<String, String>>> changes) {
        super();
        this.message = null;
        this.status = RestStatus.OK;
        this.changes = changes;
    }

    @SuppressWarnings("unchecked")
    public GetPromoteResponse(StreamInput sin) throws IOException {
        super(sin);
        this.status = sin.readEnum(RestStatus.class);
        this.message = sin.readOptionalString();
        if (sin.readBoolean()) {
            this.changes = (Map<String, List<Map<String, String>>>) sin.readGenericValue();
        } else {
            this.changes = null;
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(status);
        out.writeOptionalString(message);
        if (changes != null) {
            out.writeBoolean(true);
            out.writeGenericValue(changes);
        } else {
            out.writeBoolean(false);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (changes != null) {
            builder.field(Constants.KEY_CHANGES, changes);
        } else {
            builder.field(Constants.KEY_MESSAGE, message);
            builder.field(Constants.KEY_STATUS, status.getStatus());
        }
        return builder.endObject();
    }

    public String getMessage() {
        return message;
    }

    public RestStatus getStatus() {
        return status;
    }

    public Map<String, List<Map<String, String>>> getChanges() {
        return changes;
    }
}
