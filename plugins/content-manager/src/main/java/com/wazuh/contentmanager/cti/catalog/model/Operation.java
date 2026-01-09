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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;

/**
 * Represents a JSON Patch operation as defined by RFC 6902. This class encapsulates a single
 * modification instruction that can be applied to a JSON document, supporting operations such as
 * add, replace, remove, move, copy, and test.
 *
 * <p>JSON Patch operations are used to describe changes to documents in a structured format,
 * enabling efficient transmission and application of incremental updates. Each operation specifies
 * what action to perform (op), where to perform it (path), and optionally what value to use or
 * where to copy/move from.
 *
 * <p>This class implements ToXContentObject to support serialization and deserialization within the
 * OpenSearch ecosystem, enabling patch operations to be stored, transmitted, and applied to indexed
 * documents.
 */
public class Operation implements ToXContentObject {
    /** Field name for the operation type in JSON serialization. */
    public static final String OP = "op";

    /** Field name for the target path in JSON serialization. */
    public static final String PATH = "path";

    /** Field name for the source path in move/copy operations in JSON serialization. */
    public static final String FROM = "from";

    /** Field name for the operation value in JSON serialization. */
    public static final String VALUE = "value";

    /** The operation type (e.g., "add", "replace", "remove", "move", "copy", "test"). */
    private final String op;

    /** JSON Pointer string indicating the target location for the operation. */
    private final String path;

    /** JSON Pointer string indicating the source location for move/copy operations. */
    private final String from;

    /** The value to be used in add, replace, or test operations. */
    private final Object value;

    /**
     * Constructs a new JSON Patch Operation with the specified parameters.
     *
     * <p>Different operation types require different parameters. For example, "add" and "replace"
     * require op, path, and value, while "remove" only requires op and path. The "move" and "copy"
     * operations require op, path, and from.
     *
     * @param op The operation type to perform (e.g., "add", "replace", "remove", "move", "copy",
     *     "test").
     * @param path A JSON Pointer string (RFC 6901) indicating the target location to perform the
     *     operation.
     * @param from A JSON Pointer string indicating the source location for move/copy operations
     *     (optional, only used with "move" and "copy" operations).
     * @param value The value to be added, replaced, or tested (optional, used with "add", "replace",
     *     and "test" operations).
     */
    @JsonCreator
    public Operation(
            @JsonProperty(OP) String op,
            @JsonProperty(PATH) String path,
            @JsonProperty(FROM) String from,
            @JsonProperty(VALUE) Object value) {
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
