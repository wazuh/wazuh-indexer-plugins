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

/**
 * Response for a policy update. Carries the outcome message and HTTP status, plus a {@code
 * reloadEngine} flag signalling whether the standard-space hash changed so the caller can reload
 * the Engine.
 */
public class PutPolicyResponse extends ActionResponse implements ToXContent {
    private final String message;
    private final RestStatus status;
    private final boolean reloadEngine;

    /**
     * Constructs a new response.
     *
     * @param message the outcome message (policy ID on success, error message otherwise).
     * @param status the HTTP status.
     * @param reloadEngine whether the caller should reload the standard space into the Engine.
     */
    public PutPolicyResponse(String message, RestStatus status, boolean reloadEngine) {
        super();
        this.message = message;
        this.status = status;
        this.reloadEngine = reloadEngine;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public PutPolicyResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readEnum(RestStatus.class), sin.readBoolean());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.message);
        out.writeEnum(this.status);
        out.writeBoolean(this.reloadEngine);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder
                .startObject()
                .field(Constants.KEY_MESSAGE, this.message)
                .field(Constants.KEY_STATUS, this.status.getStatus())
                .endObject();
    }

    public String getMessage() {
        return this.message;
    }

    public RestStatus getStatus() {
        return this.status;
    }

    /**
     * @return whether the caller should reload the standard space into the Engine.
     */
    public boolean shouldReloadEngine() {
        return this.reloadEngine;
    }
}
