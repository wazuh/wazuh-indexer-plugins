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
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** ToXContentObject model to parse and build CTI API changes query replies. */
public class Changes implements ToXContentObject {
    private static final String JSON_DATA_KEY = "data";
    private final List<Offset> list;

    public Changes(List<Offset> list) {
        this.list = list != null ? list : new ArrayList<>();
    }

    public List<Offset> get() {
        return this.list;
    }

    public static Changes parse(XContentParser parser) throws IOException {
        List<Offset> changes = new ArrayList<>();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (JSON_DATA_KEY.equals(parser.currentName())) {
                parser.nextToken();
                XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, parser.currentToken(), parser);
                while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                    changes.add(Offset.parse(parser));
                }
            } else {
                parser.skipChildren();
            }
        }
        return new Changes(changes);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startArray(JSON_DATA_KEY);
        for (Offset change : this.list) {
            change.toXContent(builder, params);
        }
        builder.endArray();
        return builder.endObject();
    }
}
