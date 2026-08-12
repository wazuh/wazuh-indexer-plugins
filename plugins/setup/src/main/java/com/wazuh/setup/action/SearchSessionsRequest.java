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

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/** Request to search AI assistant sessions across every user, optionally restricted to one. */
public class SearchSessionsRequest extends ActionRequest {

    private final String user;
    private final int size;

    /**
     * Constructs a new request.
     *
     * @param user username to filter by, or {@code null}/blank for every user's sessions.
     * @param size maximum number of documents to return.
     */
    public SearchSessionsRequest(String user, int size) {
        super();
        this.user = user;
        this.size = size;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public SearchSessionsRequest(StreamInput sin) throws IOException {
        super(sin);
        this.user = sin.readOptionalString();
        this.size = sin.readInt();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(this.user);
        out.writeInt(this.size);
    }

    public String getUser() {
        return this.user;
    }

    public int getSize() {
        return this.size;
    }
}
