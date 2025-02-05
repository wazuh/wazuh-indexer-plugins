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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    private static final Logger log = LogManager.getLogger(Offset.class);
    private static final String CONTEXT = "context";
    private static final String OFFSET = "offset";
    private static final String RESOURCE = "resource";
    private static final String TYPE = "type";
    private static final String VERSION = "version";
    private static final String PAYLOAD = "payload";

    private final String context;
    private final Long offset;
    private final String resource;
    private final String type;
    private final Long version;
    private final Map<String, Object> payload;

    public Offset(
            String context,
            Long offset,
            String resource,
            String type,
            Long version,
            Map<String, Object> payload) {
        this.context = context;
        this.offset = offset;
        this.resource = resource;
        this.type = type;
        this.version = version;
        this.payload = payload;
    }

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

    public static Offset parse(XContentParser parser) throws IOException, IllegalArgumentException {
        String context = null;
        Long offset = null;
        String resource = null;
        String type = null;
        Long version = null;
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
                        type = parser.text();
                        break;
                    case VERSION:
                        version = parser.longValue();
                        break;
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
        return new Offset(context, offset, resource, type, version, payload);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(CONTEXT, this.context);
        builder.field(OFFSET, this.offset);
        builder.field(RESOURCE, this.resource);
        builder.field(TYPE, this.type);
        builder.field(VERSION, this.version);
        builder.field(PAYLOAD, this.payload);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Offset{" +
            "context='" + context + '\'' +
            ", offset=" + offset +
            ", resource='" + resource + '\'' +
            ", type='" + type + '\'' +
            ", version=" + version +
            ", payload=" + payload +
            '}';
    }
}
