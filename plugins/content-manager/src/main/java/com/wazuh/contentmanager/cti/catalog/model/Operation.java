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

/** Class representing a JSON Patch operation. */
public class Operation implements ToXContentObject {
    public static final String OP = "op";
    public static final String PATH = "path";
    public static final String FROM = "from";
    public static final String VALUE = "value";

    private final String op;
    private final String path;
    private final String from;
    private final Object value;

    /**
     * Constructs a new JSON Patch Operation.
     *
     * @param op The operation to perform (e.g., "add", "replace", "remove").
     * @param path A JSON Pointer string indicating the location to perform the operation.
     * @param from A JSON Pointer string indicating the location to move/copy from (optional, depends
     *     on 'op').
     * @param value The value to be added, replaced, or tested (optional, depends on 'op').
     */
    public Operation(String op, String path, String from, Object value) {
        this.op = op;
        this.path = path;
        this.from = from;
        this.value = value;
    }

    /**
     * Parses an XContent stream to create an {@code Operation} instance.
     *
     * @param parser The {@link XContentParser} to read from.
     * @return A populated {@code Operation} object.
     * @throws IOException If an I/O error occurs or the content structure is invalid.
     */
    public static Operation parse(XContentParser parser) throws IOException {
        String op = null;
        String path = null;
        String from = null;
        Object value = null;

        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, parser.currentToken(), parser);

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            switch (fieldName) {
                case OP -> op = parser.text();
                case PATH -> path = parser.text();
                case FROM -> from = parser.text();
                case VALUE -> {
                    switch (parser.currentToken()) {
                        case START_OBJECT -> value = parser.map();
                        case START_ARRAY -> value = parser.list();
                        case VALUE_STRING -> value = parser.text();
                        case VALUE_NUMBER -> value = parser.numberValue();
                        case VALUE_BOOLEAN -> value = parser.booleanValue();
                        case VALUE_NULL -> value = null;
                        default -> parser.skipChildren();
                    }
                }
                default -> parser.skipChildren();
            }
        }
        return new Operation(op, path, from, value);
    }

    /**
     * Serializes this operation into an {@link XContentBuilder}.
     *
     * @param builder The builder to write to.
     * @param params Contextual parameters for the serialization.
     * @return The builder instance for chaining.
     * @throws IOException If an error occurs while writing to the builder.
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(OP, this.op);
        builder.field(PATH, this.path);
        if (this.from != null) {
            builder.field(FROM, this.from);
        }
        if (this.value != null) {
            builder.field(VALUE, this.value);
        }
        return builder.endObject();
    }
}
