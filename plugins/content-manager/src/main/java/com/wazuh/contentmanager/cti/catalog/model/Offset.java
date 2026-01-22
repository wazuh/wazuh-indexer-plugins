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
import java.util.*;

/**
 * Data Transfer Object representing a change offset from the CTI API.
 *
 * <p>This class encapsulates a single synchronization event, defining what action took place
 * (Create, Update, Delete), which resource was affected, and the data associated with that change
 * (either a full payload or a list of patch operations).
 */
public class Offset implements ToXContentObject {
    private static final String CONTEXT = "context";
    private static final String OFFSET = "offset";
    private static final String RESOURCE = "resource";
    private static final String TYPE = "type";
    private static final String VERSION = "version";
    private static final String OPERATIONS = "operations";
    private static final String PAYLOAD = "payload";

    private final String context;
    private final long offset;
    private final String resource;
    private final Offset.Type type;
    private final long version;
    private final List<Operation> operations;
    private final Map<String, Object> payload;

    /**
     * Defines the type of modification operation performed on a resource in the CTI catalog. This
     * enum is used to identify whether a change event represents resource creation, update, or
     * deletion.
     */
    public enum Type {
        /** Indicates a new resource was created in the CTI catalog. */
        CREATE,

        /** Indicates an existing resource was modified in the CTI catalog. */
        UPDATE,

        /** Indicates a resource was removed from the CTI catalog. */
        DELETE;

        /**
         * Parses the type from a string value, case-insensitive.
         *
         * @param value The string value to parse.
         * @return The corresponding Type enum constant.
         */
        @JsonCreator
        public static Type fromString(String value) {
            return value == null ? null : Type.valueOf(value.toUpperCase(Locale.ROOT));
        }
    }

    /**
     * Constructs a new Offset instance.
     *
     * @param context The context or category of the content (e.g., catalog ID).
     * @param offset The sequential ID of this event. Defaults to 0 if null.
     * @param resource The unique identifier of the specific resource being modified.
     * @param type The type of modification (CREATE, UPDATE, DELETE).
     * @param version The version number of the resource. Defaults to 0 if null.
     * @param operations A list of patch operations (typically used with UPDATE).
     * @param payload The full resource content (typically used with CREATE).
     */
    @JsonCreator
    public Offset(
        @JsonProperty(CONTEXT) String context,
        @JsonProperty(OFFSET) long offset,
        @JsonProperty(RESOURCE) String resource,
        @JsonProperty(TYPE) Type type,
        @JsonProperty(VERSION) long version,
        @JsonProperty(OPERATIONS) List<Operation> operations,
        @JsonProperty(PAYLOAD) Map<String, Object> payload) {
        this.context = context;
        this.offset = offset;
        this.resource = resource;
        this.type = type;
        this.version = version;
        this.operations = operations;
        this.payload = payload;
    }

    /**
     * Parses an XContent stream to create an {@code Offset} instance.
     *
     * @param parser The {@link XContentParser} to read from.
     * @return A populated {@code Offset} object.
     * @throws IOException If an I/O error occurs or the JSON structure is invalid.
     */
    public static Offset parse(XContentParser parser) throws IOException {
        String context = null;
        Long offset = null;
        String resource = null;
        Type type = null;
        Long version = null;
        List<Operation> operations = new ArrayList<>();
        Map<String, Object> payload = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken() == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case CONTEXT -> context = parser.text();
                    case OFFSET -> offset = parser.longValue();
                    case RESOURCE -> resource = parser.text();
                    case TYPE -> type = Type.valueOf(parser.text().trim().toUpperCase(Locale.ROOT));
                    case VERSION -> version = parser.longValue();
                    case OPERATIONS -> {
                        XContentParserUtils.ensureExpectedToken(
                            XContentParser.Token.START_ARRAY, parser.currentToken(), parser);
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            operations.add(Operation.parse(parser));
                        }
                    }
                    case PAYLOAD -> {
                        if (parser.currentToken() == XContentParser.Token.START_OBJECT) {
                            payload = parser.map();
                        }
                    }
                    default -> parser.skipChildren();
                }
            }
        }
        return new Offset(
            context,
            offset != null ? offset : 0,
            resource,
            type,
            version != null ? version : 0,
            operations,
            payload);
    }

    /**
     * Gets the unique identifier of the resource affected by this change.
     *
     * @return The resource ID string.
     */
    public String getResource() {
        return this.resource;
    }

    /**
     * Gets the type of modification performed.
     *
     * @return The {@link Type} enum value (CREATE, UPDATE, DELETE).
     */
    public Type getType() {
        return this.type;
    }

    /**
     * Gets the list of patch operations associated with this change.
     *
     * @return A list of {@link Operation} objects, or an empty list if none exist.
     */
    public List<Operation> getOperations() {
        return this.operations;
    }

    /**
     * Gets the sequential offset ID of this change event.
     *
     * @return The offset value as a long.
     */
    public long getOffset() {
        return this.offset;
    }

    /**
     * Gets the full content payload of the resource.
     *
     * @return A Map representing the resource JSON, or null if not present.
     */
    public Map<String, Object> getPayload() {
        return this.payload;
    }

    /**
     * Serializes this object into an {@link XContentBuilder}.
     *
     * @param builder The builder to write to.
     * @param params Contextual parameters for the serialization.
     * @return The builder instance for chaining.
     * @throws IOException If an error occurs while writing to the builder.
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (this.context != null) {
            builder.field(CONTEXT, this.context);
        }
        builder.field(OFFSET, this.offset);
        if (this.resource != null) {
            builder.field(RESOURCE, this.resource);
        }
        if (this.type != null) {
            builder.field(TYPE, this.type);
        }
        builder.field(VERSION, this.version);
        if (this.operations != null) {
            builder.startArray(OPERATIONS);
            for (Operation op : this.operations) {
                op.toXContent(builder, params);
            }
            builder.endArray();
        }
        if (this.payload != null) {
            builder.field(PAYLOAD, this.payload);
        }
        return builder.endObject();
    }
}
