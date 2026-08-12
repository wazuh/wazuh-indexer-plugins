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
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Response carrying the sessions matched by a {@link SearchSessionsRequest}. */
public class SearchSessionsResponse extends ActionResponse implements ToXContent {
    private static final String TOTAL = "total";
    private static final String SESSIONS = "sessions";

    private final long total;
    private final List<Map<String, Object>> sessions;

    /**
     * Constructs a new response.
     *
     * @param total total number of matching documents, before the size cap was applied.
     * @param sessions the matched documents, each map holding the document's {@code _source} plus its
     *     {@code _id}.
     */
    public SearchSessionsResponse(long total, List<Map<String, Object>> sessions) {
        super();
        this.total = total;
        this.sessions = sessions;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public SearchSessionsResponse(StreamInput sin) throws IOException {
        super();
        this.total = sin.readLong();
        int count = sin.readVInt();
        this.sessions = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            this.sessions.add(sin.readMap());
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeLong(this.total);
        out.writeVInt(this.sessions.size());
        for (Map<String, Object> session : this.sessions) {
            out.writeMap(session);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field(TOTAL, this.total).startArray(SESSIONS);
        for (Map<String, Object> session : this.sessions) {
            builder.map(session);
        }
        return builder.endArray().endObject();
    }

    public long getTotal() {
        return this.total;
    }

    public List<Map<String, Object>> getSessions() {
        return this.sessions;
    }
}
