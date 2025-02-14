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

public class Document implements ToXContentObject {
    private static final String CONSUMER_NAME = "vd_4.8.0";

    private Consumer consumer;

    public Document(Consumer consumer) {
        this.consumer = consumer;
    }

    public static Document parse(XContentParser parser) throws IOException {
        Consumer consumer = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentName().equals(CONSUMER_NAME)) {
                consumer = Consumer.parse(parser);
            }
        }
        return new Document(consumer);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(CONSUMER_NAME, consumer);
        return builder.endObject();
    }
}
