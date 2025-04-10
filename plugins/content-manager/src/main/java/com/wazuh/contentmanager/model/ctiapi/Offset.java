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

import org.opensearch.core.common.ParsingException;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Offset implements ToXContentObject {

    private static final String CONTEXT = "context";
    private static final String OFFSET = "offset";
    private static final String RESOURCE = "resource";
    private static final String TYPE = "type";
    private static final String VERSION = "version";
    private static final String OPERATIONS = "operations";
    private static final String PAYLOAD = "payload";
    private final String context;
    private final Long offset;
    private final String resource;
    private final ContentType type;
    private final Long version;
    private final List<PatchOperation> operations;
    private final Map<String, Object> payload;

    /**
     * Constructor for the class
     *
     * @param context Name of the context
     * @param offset Offset number of the record
     * @param resource Name of the resource
     * @param type ContentType of operation to be performed
     * @param version Version Number
     * @param operations JSON Patch payload data
     */
    public Offset(
            String context,
            Long offset,
            String resource,
            ContentType type,
            Long version,
            List<PatchOperation> operations,
            Map<String, Object> payload) {
        this.context = context;
        this.offset = offset;
        this.resource = resource;
        this.type = type;
        this.version = version;
        this.operations = operations;
        this.payload = payload;
    }

    public static Offset parse(XContentParser parser)
            throws IllegalArgumentException, ParsingException, IOException {
        String context = null;
        Long offset = null;
        String resource = null;
        ContentType type = null;
        Long version = null;
        List<PatchOperation> operations = new ArrayList<>();
        Map<String, Object> payload = new HashMap<>();
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken() == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case CONTEXT:
                        context = parser.text();
                        break;
                    case OFFSET:
                        offset = parser.longValue();
                        break;
                    case RESOURCE:
                        resource = parser.text();
                        break;
                    case TYPE:
                        type = ContentType.fromString(parser.text());
                        break;
                    case VERSION:
                        version = parser.longValue();
                        break;
                    case OPERATIONS:
                        XContentParserUtils.ensureExpectedToken(
                                XContentParser.Token.START_ARRAY, parser.nextToken(), parser);
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            operations.add(PatchOperation.parse(parser));
                        }
                    case PAYLOAD:
                        XContentParserUtils.ensureExpectedToken(
                                XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                        payload = parseObject(parser);
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }
        return new Offset(context, offset, resource, type, version, operations, payload);
    }

    private static Map<String, Object> parseObject(XContentParser parser) throws IOException {
        Map<String, Object> result = new HashMap<>();
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken() == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                switch (parser.nextToken()) {
                    case START_OBJECT:
                        result.put(fieldName, parseObject(parser));
                        break;
                    case START_ARRAY:
                        result.put(fieldName, parseArray(parser));
                        break;
                    case VALUE_STRING:
                        result.put(fieldName, parser.text());
                        break;
                    case VALUE_NUMBER:
                        result.put(fieldName, parser.numberValue());
                        break;
                    case VALUE_BOOLEAN:
                        result.put(fieldName, parser.booleanValue());
                        break;
                    case VALUE_NULL:
                        result.put(fieldName, null);
                        break;
                    default:
                        parser.skipChildren();
                }
            }
        }
        return result;
    }

    /**
     * A method to parse arrays recursively
     *
     * @param parser an XContentParser containing an array
     * @return the parsed list as a List
     * @throws IOException rethrown from parseObject
     */
    private static List<Object> parseArray(XContentParser parser) throws IOException {
        List<Object> array = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            switch (parser.currentToken()) {
                case START_OBJECT:
                    array.add(parseObject(parser));
                    break;
                case START_ARRAY:
                    array.add(parseArray(parser));
                    break;
                case VALUE_STRING:
                    array.add(parser.text());
                    break;
                case VALUE_NUMBER:
                    array.add(parser.numberValue());
                    break;
                case VALUE_BOOLEAN:
                    array.add(parser.booleanValue());
                    break;
                case VALUE_NULL:
                    array.add(null);
                    break;
                default:
                    parser.skipChildren();
            }
        }

        return array;
    }

    /**
     * Getter for the offset
     *
     * @return the offset as a Long
     */
    public Long getOffset() {
        return this.offset;
    }

    /**
     * Getter for the resource name
     *
     * @return the resource name as a String
     */
    public String getResource() {
        return this.resource;
    }

    /**
     * Getter for the type
     *
     * @return the type as a String
     */
    public ContentType getType() {
        return this.type;
    }

    /**
     * Getter for the context name
     *
     * @return the context name as a String
     */
    public String getContext() {
        return this.context;
    }

    /**
     * Getter for the operations
     *
     * @return the operations as a List of JsonPatch
     */
    public List<PatchOperation> getOperations() {
        return this.operations;
    }

    /**
     * Getter for the version
     *
     * @return the version as a Long
     */
    public Long getVersion() {
        return this.version;
    }

    /**
     * Getter for the payload
     *
     * @return the payload as mapping
     */
    public Map<String, Object> getPayload() {
        return this.payload;
    }

    /**
     * Outputs an XContentBuilder object ready to be printed or manipulated
     *
     * @param builder the received builder object
     * @param params We don't really use this one
     * @return an XContentBuilder object ready to be printed
     * @throws IOException rethrown from Offset's toXContent
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(CONTEXT, this.context);
        builder.field(OFFSET, this.offset);
        builder.field(RESOURCE, this.resource);
        builder.field(TYPE, this.type);
        builder.field(VERSION, this.version);
        builder.startArray(OPERATIONS);
        if (this.operations != null) {
            for (PatchOperation operation : operations) {
                operation.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
            }
        }
        builder.endArray();
        builder.field(PAYLOAD, this.payload);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "PatchChange{"
                + "context='"
                + context
                + '\''
                + ", offset="
                + offset
                + ", resource='"
                + resource
                + '\''
                + ", type='"
                + type
                + '\''
                + ", version="
                + version
                + ", operations="
                + operations
                + '\''
                + ", payload="
                + payload
                + '}';
    }
}
