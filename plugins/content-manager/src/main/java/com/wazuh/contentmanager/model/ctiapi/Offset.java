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

import java.io.IOException;

public class Offset implements ToXContentObject {

    private static final Logger log = LogManager.getLogger(Offset.class);
    private static final String CONTEXT = "context";
    private static final String OFFSET = "offset";
    private static final String RESOURCE = "resource";
    private static final String TYPE = "type";
    private static final String VERSION = "version";
    private static final String PAYLOAD = "payload";

    private static String context;
    private static Long offset;
    private static String resource;
    private static String type;
    private static Long version;
    private static Object payload;

    public Offset(
            String context,
            Long offset,
            String resource,
            String type,
            Long version,
            Object payload) {
        this.context = context;
        this.offset = offset;
        this.resource = resource;
        this.type = type;
        this.version = version;
        this.payload = payload;
    }

    private static void processArray(XContentParser parser) throws IOException {
        log.info("Entering an array...");
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            if (parser.currentToken() == XContentParser.Token.START_OBJECT) {
                processObject(parser); // Handle nested objects in arrays
            } else if (parser.currentToken() == XContentParser.Token.START_ARRAY) {
                processArray(parser); // Handle nested arrays
            } else {
                log.info("Array value: " + parser.text());
            }
        }
        log.info("Exiting an array...");
    }

    private static void processObject(XContentParser parser) throws IOException {
        log.info("Entering an object...");
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken() == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken(); // Move to value
                log.info("Field: " + fieldName);

                if (parser.currentToken() == XContentParser.Token.START_OBJECT) {
                    processObject(parser); // Recursively handle nested objects
                } else if (parser.currentToken() == XContentParser.Token.START_ARRAY) {
                    processArray(parser); // Recursively handle nested arrays
                } else {
                    log.info("Value: " + parser.text());
                }
            }
        }
        log.info("Exiting an object...");
    }

    public static Offset parse(XContentParser parser) throws IOException, IllegalArgumentException {
        String context = null;
        Long offset = null;
        String resource = null;
        String type = null;
        Long version = null;
        Object payload = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
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
                        if (parser.currentToken() == XContentParser.Token.START_OBJECT) {
                            parser.nextToken();
                            processObject(parser);
                        }
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
}
