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

/**
 * This class acts as a wrapper for a list of {@link Offset} objects.
 */
public class Changes implements ToXContentObject {
    private static final String JSON_DATA_KEY = "data";
    private final List<Offset> list;

    /**
     * Constructs a new Changes object with the specified list of offsets.
     *
     * @param list The list of {@link Offset} objects. If null, an empty list is initialized.
     */
    public Changes(List<Offset> list) {
        this.list = list != null ? list : new ArrayList<>();
    }

    /**
     * Retrieves the list of changes.
     *
     * @return The list of {@link Offset} objects.
     */
    public List<Offset> get() {
        return this.list;
    }

    /**
     * Parses an XContent stream to create a {@code Changes} instance.
     * <p>
     * This method expects the parser to be positioned at the start of a JSON object.
     * It looks for a field named "data" (defined by {@code JSON_DATA_KEY}), which
     * must be an array of {@link Offset} objects.
     *
     * @param parser The {@link XContentParser} to read from.
     * @return A populated {@code Changes} object.
     * @throws IOException If an I/O error occurs or the content structure is invalid.
     */
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

    /**
     * Serializes this object into an {@link XContentBuilder}.
     *
     * @param builder The builder to write to.
     * @param params  Contextual parameters for the serialization.
     * @return The builder instance for chaining.
     * @throws IOException If an error occurs while writing to the builder.
     */
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
