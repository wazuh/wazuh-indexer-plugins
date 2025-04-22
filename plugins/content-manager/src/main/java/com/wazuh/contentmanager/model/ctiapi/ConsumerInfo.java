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
package com.wazuh.contentmanager.model.ctiapi;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

/** ToXContentObject model to parse and build CTI API Catalog query replies */
public class ConsumerInfo implements ToXContentObject {

    public static final String ID = "id";
    public static final String CONTEXT = "context";
    public static final String NAME = "name";
    public static final String LAST_OFFSET = "last_offset";
    public static final String OFFSET = "offset";
    public static final String PATHS_FILTER = "paths_filter";
    public static final String LAST_SNAPSHOT_LINK = "last_snapshot_link";
    public static final String LAST_SNAPSHOT_OFFSET = "last_snapshot_offset";
    public static final String LAST_SNAPSHOT_AT = "last_snapshot_at";
    public static final String CHANGES_URL = "changes_url";
    public static final String INSERTED_AT = "inserted_at";
    public static final String DATA = "data";
    public static final String UPDATED_AT = "updated_at";
    public static final String OPERATIONS = "operations";
    private final String context;
    private final String name;
    private final Long offset;
    private final Long lastOffset;
    private final String lastSnapshotLink;

    /**
     * Constructor method
     *
     * @param name Name of the consumer
     * @param context Name of the context
     * @param offset The current offset number
     * @param lastOffset The last offset number
     * @param lastSnapshotLink URL link to the latest snapshot
     */
    public ConsumerInfo(
            String name, String context, Long offset, Long lastOffset, String lastSnapshotLink) {
        this.name = name;
        this.context = context;
        this.offset = offset;
        this.lastOffset = lastOffset;
        this.lastSnapshotLink = lastSnapshotLink;
    }

    /**
     * Parses a Catalog CTI API reply from an XContentParser
     *
     * @param parser the incoming parser
     * @return a fully parsed ConsumerInfo object
     * @throws IOException rethrown from parse()
     * @throws IllegalArgumentException rethrown from parse()
     */
    public static ConsumerInfo parse(XContentParser parser)
            throws IOException, IllegalArgumentException {
        String context = null;
        String name = null;
        long lastOffset = 0L;
        // We are initializing the offset to 0
        long offset = 0L;
        String lastSnapshotLink = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case DATA:
                    case ID:
                    case OPERATIONS:
                    case INSERTED_AT:
                    case UPDATED_AT:
                    case PATHS_FILTER:
                    case CHANGES_URL:
                    case LAST_SNAPSHOT_AT:
                    case LAST_SNAPSHOT_OFFSET:
                        break;
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

    /**
     * Creates an XContentBuilder for the parsed object
     *
     * @param builder Incoming builder to add the fields to
     * @param params Not used
     * @return a valid XContentBuilder object ready to be turned into JSON
     * @throws IOException rethrown from XContentBuilder methods
     */
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

    @Override
    public String toString() {
        return "ConsumerInfo{"
                + "context='"
                + context
                + '\''
                + ", name='"
                + name
                + '\''
                + ", lastOffset="
                + lastOffset
                + ", lastSnapshotLink='"
                + lastSnapshotLink
                + '\''
                + '}';
    }

    /**
     * Getter for the context name
     *
     * @return Context name as a String
     */
    public String getContext() {
        return this.context;
    }

    /**
     * Getter for the last offset number
     *
     * @return Last offset number as a long
     */
    public long getLastOffset() {
        return this.lastOffset;
    }

    /**
     * Get the current offset number
     *
     * @return The offset as a Long value
     */
    public Long getOffset() {
        return offset;
    }

    /**
     * Retrieves the URL of the last consumer snapshot
     *
     * @return A Snapshot URL
     */
    public String getLastSnapshotLink() {
        return this.lastSnapshotLink;
    }

    /**
     * Retrieves the name of the consumer
     *
     * @return The name of the consumer
     */
    public String getName() {
        return this.name;
    }
}
