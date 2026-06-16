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

import com.wazuh.contentmanager.utils.Constants;

public class IndexSubscriptionResponse extends ActionResponse implements ToXContent {
    private final String message;
    private final RestStatus status;

    public IndexSubscriptionResponse(String message, RestStatus status) {
        super();
        this.message = message;
        this.status = status;
    }

    public IndexSubscriptionResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readEnum(RestStatus.class));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(message);
        out.writeEnum(status);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        // builder.startObject().field(_ID, id).field(_VERSION, version);
        return builder
                .startObject()
                .field(Constants.KEY_MESSAGE, message)
                .field(Constants.KEY_STATUS, status.getStatus())
                .endObject();
    }

    public String getMessage() {
        return message;
    }

    public RestStatus getStatus() {
        return status;
    }
}
