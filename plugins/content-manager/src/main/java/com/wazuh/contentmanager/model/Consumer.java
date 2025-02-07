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
package com.wazuh.contentmanager.model;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

public class Consumer implements ToXContentObject {
    private static final String OFFSET = "offset";
    private static final String LAST_OFFSET = "last_offset";
    private static final String SNAPSHOT = "snapshot";
    private static final String HASH = "hash";

    private final Integer offset;
    private final Integer lastOffset;
    private final String snapshot;
    private final String hash;

    public Consumer(Integer offset, Integer lastOffset, String snapshot, String hash) {
        this.offset = offset;
        this.lastOffset = lastOffset;
        this.snapshot = snapshot;
        this.hash = hash;
    }

    public static Consumer parse(XContentParser parser) throws IOException {
        Integer offset = null;
        Integer lastOffset = null;
        String snapshot = null;
        String hash = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                String fieldName = parser.currentName();

                parser.nextToken();
                switch (fieldName) {
                    case OFFSET:
                        offset = parser.intValue();
                        break;
                    case LAST_OFFSET:
                        lastOffset = parser.intValue();
                        break;
                    case SNAPSHOT:
                        snapshot = parser.text();
                        break;
                    case HASH:
                        hash = parser.text();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }
        return new Consumer(offset, lastOffset, snapshot, hash);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(OFFSET, this.offset);
        builder.field(LAST_OFFSET, this.lastOffset);
        builder.field(SNAPSHOT, this.snapshot);
        builder.field(HASH, this.hash);
        return builder.endObject();
    }
}
