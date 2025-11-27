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
    private static final String ID = "id";
    private static final String CONTEXT = "context";
    private static final String NAME = "name";
    public static final String LAST_OFFSET = "last_offset";
    public static final String OFFSET = "offset";
    private static final String PATHS_FILTER = "paths_filter";
    public static final String LAST_SNAPSHOT_LINK = "last_snapshot_link";
    private static final String LAST_SNAPSHOT_OFFSET = "last_snapshot_offset";
    private static final String LAST_SNAPSHOT_AT = "last_snapshot_at";
    private static final String CHANGES_URL = "changes_url";
    private static final String INSERTED_AT = "inserted_at";
    private static final String DATA = "data";
    private static final String UPDATED_AT = "updated_at";
    private static final String OPERATIONS = "operations";
    private final String context;
    private final String name;
    private long offset;
    private long lastOffset;
    private String lastSnapshotLink;

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
        this.setOffset(offset);
        this.setLastOffset(lastOffset);
        this.lastSnapshotLink = lastSnapshotLink;
    }

    /**
     * Parses the consumer's information within an XContentParser (reply from the CTI API).
     *
     * @param parser the incoming parser.
     * @return a fully parsed ConsumerInfo object.
     * @throws IOException rethrown from parse().
     * @throws IllegalArgumentException rethrown from parse().
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
        builder.field(ConsumerInfo.LAST_OFFSET, this.lastOffset);
        builder.field(ConsumerInfo.LAST_SNAPSHOT_LINK, this.lastSnapshotLink);
        builder.field(ConsumerInfo.OFFSET, this.offset);
        builder.endObject();
        return builder.endObject();
    }

    /**
     * {@link ConsumerInfo#context} getter.
     *
     * @return the consumer's context name.
     */
    public String getContext() {
        return this.context;
    }

    /**
     * {@link ConsumerInfo#name} getter.
     *
     * @return the consumer's name.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Get the latest consumer's offset (as last fetched from the CTI API).
     *
     * @return Consumer's latest available offset.
     */
    public long getLastOffset() {
        return this.lastOffset;
    }

    /**
     * Get the consumer's offset (in Indexer).
     *
     * @return The consumer's offset.
     */
    public long getOffset() {
        return this.offset;
    }

    /**
     * Get the URL of the latest consumer's snapshot.
     *
     * @return URL string.
     */
    public String getLastSnapshotLink() {
        return this.lastSnapshotLink;
    }

    /**
     * {@link ConsumerInfo#offset} setter.
     *
     * @param offset new value (positive).
     * @throws IllegalArgumentException when {@code offset < 0}.
     */
    public void setOffset(long offset) throws IllegalArgumentException {
        if (offset < 0) {
            throw new IllegalArgumentException("Offset can't be negative");
        }
        this.offset = offset;
    }

    /**
     * {@link ConsumerInfo#lastOffset} setter.
     *
     * @param offset new value (positive).
     * @throws IllegalArgumentException when {@code offset < 0}.
     */
    public void setLastOffset(long offset) throws IllegalArgumentException {
        if (offset < 0) {
            throw new IllegalArgumentException("Offset can't be negative");
        }
        this.lastOffset = offset;
    }

    /**
     * {@link ConsumerInfo#lastSnapshotLink} setter.
     *
     * @param url new value (URL).
     */
    public void setLastSnapshotLink(String url) {
        this.lastSnapshotLink = url;
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
                + ", offset="
                + offset
                + ", lastOffset="
                + lastOffset
                + ", lastSnapshotLink='"
                + lastSnapshotLink
                + '\''
                + '}';
    }
}
