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
import java.util.List;

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
    private final Long lastOffset;
    private final String lastSnapshotLink;

    /**
     * Constructor method
     *
     * @param name Name of the consumer
     * @param context Name of the context
     * @param lastOffset The last offset number
     * @param lastSnapshotLink URL link to the latest snapshot
     */
    public ConsumerInfo(
            String name,
            String context,
            Long lastOffset,
            String lastSnapshotLink) {
        this.name = name;
        this.context = context;
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
        String lastSnapshotLink = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case DATA:
                        break;
                    case ID:
                        break;
                    case NAME:
                        name = parser.text();
                        break;
                    case CONTEXT:
                        context = parser.text();
                        break;
                    case OPERATIONS:
                        break;
                    case INSERTED_AT:
                        break;
                    case UPDATED_AT:
                        break;
                    case PATHS_FILTER:
                        break;
                    case LAST_OFFSET:
                        lastOffset = parser.longValue();
                        break;
                    case CHANGES_URL:
                        break;
                    case LAST_SNAPSHOT_AT:
                        break;
                    case LAST_SNAPSHOT_LINK:
                        lastSnapshotLink = parser.text();
                        break;
                    case LAST_SNAPSHOT_OFFSET:
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }
        return new ConsumerInfo(
                name,
                context,
                lastOffset,
                lastSnapshotLink
                );
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
        builder.field(OFFSET, 0);
        builder.endObject();
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "ConsumerInfo{" +
            "context='" + context + '\'' +
            ", name='" + name + '\'' +
            ", lastOffset=" + lastOffset +
            ", lastSnapshotLink='" + lastSnapshotLink + '\'' +
            '}';
    }

    public String getContext() {
        return context;
    }

    public String getLastSnapshotLink() {
        return lastSnapshotLink;
    }
}
