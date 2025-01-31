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

public class ContextConsumerCatalog implements ToXContentObject {

    public static final String ID = "id";
    public static final String CONTEXT = "context";
    public static final String NAME = "name";
    public static final String LAST_OFFSET = "last_offset";
    public static final String PATHS_FILTER = "paths_filter";
    public static final String LAST_SNAPSHOT_LINK = "last_snapshot_link";
    public static final String LAST_SNAPSHOT_OFFSET = "last_snapshot_offset";
    public static final String LAST_SNAPSHOT_AT = "last_snapshot_at";
    public static final String CHANGES_URL = "changes_url";
    public static final String INSERTED_AT = "inserted_at";
    public static final String DATA = "data";
    public static final String UPDATED_AT = "updated_at";
    public static final String OPERATIONS = "operations";
    private final Long id;
    private final String context;
    private final String name;
    private final Long lastOffset;
    private final List<Object> pathsFilter;
    private final String lastSnapshotLink;
    private final Long lastSnapshotOffset;
    private final String lastSnapshotAt;
    private final String changesUrl;
    private final String insertedAt;
    private final List<Object> operations;
    private final String updatedAt;

    public ContextConsumerCatalog(
            Long id,
            String name,
            String context,
            List<Object> operations,
            String insertedAt,
            String updatedAt,
            List<Object> pathsFilter,
            Long lastOffset,
            String changesUrl,
            String lastSnapshotAt,
            String lastSnapshotLink,
            Long lastSnapshotOffset) {
        this.id = id;
        this.name = name;
        this.context = context;
        this.operations = operations;
        this.insertedAt = insertedAt;
        this.updatedAt = updatedAt;
        this.pathsFilter = pathsFilter;
        this.lastOffset = lastOffset;
        this.changesUrl = changesUrl;
        this.lastSnapshotAt = lastSnapshotAt;
        this.lastSnapshotLink = lastSnapshotLink;
        this.lastSnapshotOffset = lastSnapshotOffset;
    }

    public ContextConsumerCatalog parse(XContentParser parser)
            throws IOException, IllegalArgumentException {
        long id = 0L;
        String context = null;
        String name = null;
        long lastOffset = 0L;
        List<Object> pathsFilter = null;
        String lastSnapshotLink = null;
        long lastSnapshotOffset = 0L;
        String lastSnapshotAt = null;
        String changesUrl = null;
        String insertedAt = null;
        String updatedAt = null;
        List<Object> operations = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case ID:
                        id = parser.longValue();
                        break;
                    case NAME:
                        name = parser.text();
                        break;
                    case CONTEXT:
                        context = parser.text();
                        break;
                    case OPERATIONS:
                        operations = parser.list();
                        break;
                    case INSERTED_AT:
                        insertedAt = parser.text();
                        break;
                    case UPDATED_AT:
                        updatedAt = parser.text();
                        break;
                    case PATHS_FILTER:
                        pathsFilter = parser.list();
                        break;
                    case LAST_OFFSET:
                        lastOffset = parser.longValue();
                        break;
                    case CHANGES_URL:
                        changesUrl = parser.text();
                        break;
                    case LAST_SNAPSHOT_AT:
                        lastSnapshotAt = parser.text();
                        break;
                    case LAST_SNAPSHOT_LINK:
                        lastSnapshotLink = parser.text();
                        break;
                    case LAST_SNAPSHOT_OFFSET:
                        lastSnapshotOffset = parser.longValue();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }
        return new ContextConsumerCatalog(
                id,
                name,
                context,
                operations,
                insertedAt,
                updatedAt,
                pathsFilter,
                lastOffset,
                changesUrl,
                lastSnapshotAt,
                lastSnapshotLink,
                lastSnapshotOffset);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(DATA);
        builder.field(ID, this.id);
        builder.field(NAME, this.name);
        builder.field(CONTEXT, this.context);
        builder.field(OPERATIONS, this.operations);
        builder.field(INSERTED_AT, this.insertedAt);
        builder.field(UPDATED_AT, this.updatedAt);
        builder.field(PATHS_FILTER, this.pathsFilter);
        builder.field(LAST_OFFSET, this.lastOffset);
        builder.field(CHANGES_URL, this.changesUrl);
        builder.field(LAST_SNAPSHOT_AT, this.lastSnapshotAt);
        builder.field(LAST_SNAPSHOT_LINK, this.lastSnapshotLink);
        builder.field(LAST_SNAPSHOT_OFFSET, this.lastSnapshotOffset);
        return builder.endObject();
    }
}
