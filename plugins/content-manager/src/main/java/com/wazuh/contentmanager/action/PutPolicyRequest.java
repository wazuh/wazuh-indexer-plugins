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

import java.io.IOException;

/** Request carrying the target space and the raw policy payload for a policy update. */
public class PutPolicyRequest extends ActionRequest {

    private final String space;
    private final String payload;

    /**
     * Constructs a new request.
     *
     * @param space the target space ({@code draft} or {@code standard}).
     * @param payload the raw JSON request body.
     */
    public PutPolicyRequest(String space, String payload) {
        super();
        this.space = space;
        this.payload = payload;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public PutPolicyRequest(StreamInput sin) throws IOException {
        super(sin);
        this.space = sin.readOptionalString();
        this.payload = sin.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(this.space);
        out.writeOptionalString(this.payload);
    }

    public String getSpace() {
        return this.space;
    }

    public String getPayload() {
        return this.payload;
    }
}
