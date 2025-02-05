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
package com.wazuh.contentmanager.model.index;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

public class Consumer implements ToXContentObject {

    public static final String OFFSET = "offset";
    public static final String SNAPSHOT_URL = "snapshotUrl";
    public static final String SNAPSHOT_HASH = "snapshotHash";
    private final String consumerName;
    private final Long offset;
    private final String snapshotUrl;
    private final String snapshotHash;

    public Consumer(String consumerName, Long offset, String snapshotUrl, String snapshotHash) {
        this.consumerName = consumerName;
        this.offset = offset;
        this.snapshotUrl = snapshotUrl;
        this.snapshotHash = snapshotHash;
    }

    public static Consumer parse(String consumerName, XContentParser parser)
            throws IOException, IllegalArgumentException {
        Long offset = 0L;
        String snapshotUrl = null;
        String snapshotHash = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case OFFSET:
                        offset = parser.longValue();
                        break;
                    case SNAPSHOT_URL:
                        snapshotUrl = parser.text();
                        break;
                    case SNAPSHOT_HASH:
                        snapshotHash = parser.text();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }

        return new Consumer(consumerName, offset, snapshotUrl, snapshotHash);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(this.consumerName);
        builder.field(OFFSET, this.offset);
        builder.field(SNAPSHOT_URL, this.snapshotUrl);
        builder.field(SNAPSHOT_HASH, this.snapshotHash);
        return builder.endObject();
    }
}
