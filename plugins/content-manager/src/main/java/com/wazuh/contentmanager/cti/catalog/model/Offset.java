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
import java.util.*;

/**
 * Data Transfer Object representing a change offset from the CTI API.
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

    public enum Type { CREATE, UPDATE, DELETE }

    public Offset(String context, Long offset, String resource, Type type, Long version, List<Operation> operations, Map<String, Object> payload) {
        this.context = context;
        this.offset = offset != null ? offset : 0;
        this.resource = resource;
        this.type = type;
        this.version = version != null ? version : 0;
        this.operations = operations;
        this.payload = payload;
    }

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
                        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, parser.currentToken(), parser);
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
        return new Offset(context, offset, resource, type, version, operations, payload);
    }

    public String getResource() { return resource; }
    public Type getType() { return type; }
    public List<Operation> getOperations() { return operations; }
    public long getOffset() { return offset; }
    public Map<String, Object> getPayload() { return payload; }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (context != null) builder.field(CONTEXT, context);
        builder.field(OFFSET, offset);
        if (resource != null) builder.field(RESOURCE, resource);
        if (type != null) builder.field(TYPE, type);
        builder.field(VERSION, version);
        if (operations != null) {
            builder.startArray(OPERATIONS);
            for (Operation op : operations) op.toXContent(builder, params);
            builder.endArray();
        }
        if (payload != null) builder.field(PAYLOAD, payload);
        return builder.endObject();
    }
}
