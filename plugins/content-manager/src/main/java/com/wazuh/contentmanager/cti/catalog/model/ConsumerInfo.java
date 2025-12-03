/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.model;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

/** ToXContentObject model to parse and build CTI API Catalog query replies */
public class ConsumerInfo implements ToXContentObject {
    private static final String CONTEXT = "context";
    private static final String NAME = "name";
    public static final String LAST_OFFSET = "last_offset";
    public static final String OFFSET = "offset";
    public static final String LAST_SNAPSHOT_LINK = "last_snapshot_link";

    private final String context;
    private final String name;
    private final long offset;
    private final long lastOffset;
    private final String lastSnapshotLink;

    /**
     * Constructor.
     *
     * @param name Name of the consumer
     * @param context Name of the context
     * @param offset The current offset number
     * @param lastOffset The last offset number
     * @param lastSnapshotLink URL link to the latest snapshot
     */
    public ConsumerInfo(
        String name, String context, long offset, long lastOffset, String lastSnapshotLink) {
        this.name = name;
        this.context = context;
        this.offset = offset;
        this.lastOffset = lastOffset;
        this.lastSnapshotLink = lastSnapshotLink;
    }

    /**
     * Parses the consumer's information within an XContentParser (reply from the CTI API).
     *
     * @param parser the incoming parser.
     * @return a fully parsed ConsumerInfo object.
     * @throws IOException rethrown from parse().
     */
    public static ConsumerInfo parse(XContentParser parser) throws IOException {
        String context = null;
        String name = null;
        long lastOffset = 0L;
        long offset = 0L;
        String lastSnapshotLink = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case NAME:
                        name = parser.text();
                        break;
                    case CONTEXT:
                        context = parser.text();
                        break;
                    case LAST_OFFSET:
                        lastOffset = parser.longValue();
                        break;
                    case LAST_SNAPSHOT_LINK:
                        lastSnapshotLink = parser.text();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }
        return new ConsumerInfo(name, context, offset, lastOffset, lastSnapshotLink);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startObject(this.name);
        builder.field(LAST_OFFSET, this.lastOffset);
        builder.field(LAST_SNAPSHOT_LINK, this.lastSnapshotLink);
        builder.field(OFFSET, this.offset);
        builder.endObject();
        return builder.endObject();
    }

    public String getContext() { return this.context; }
    public String getName() { return this.name; }
    public long getLastOffset() { return this.lastOffset; }
    public long getOffset() { return this.offset; }
    public String getLastSnapshotLink() { return this.lastSnapshotLink; }

    @Override
    public String toString() {
        return "ConsumerInfo{"
            + "context='" + context + '\''
            + ", name='" + name + '\''
            + ", offset=" + offset
            + ", lastOffset=" + lastOffset
            + ", lastSnapshotLink='" + lastSnapshotLink + '\''
            + '}';
    }
}
