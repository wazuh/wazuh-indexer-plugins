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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GenericDocument implements ToXContentObject {
    private static final Logger log = LogManager.getLogger(GenericDocument.class);

    public static final String SOURCE = "_source";

    private String id;
    private Map<String, Object> source;

    public GenericDocument(String id, Map<String, Object> source) {
        this.id = id;
        this.source = source;
    }

    /**
     * Required for the parsing of nested objects.
     *
     * @return internal args map.
     */
    public Map<String, Object> getSource() {
        return this.source;
    }

    public String getid() {
        return this.id;
    }

    /**
     * Generic command.action.args parser.
     *
     * @param parser An XContentParser containing an args to be deserialized
     * @return An Args object
     * @throws IOException Rethrows the exception from list() and objectText() method
     */
    public static GenericDocument parse(XContentParser parser) throws IOException {
        Map<String, Object> source = new HashMap<>();
        String id = null;

        String fieldName = "";
        List<Object> list = null;
        boolean isList = false;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParser.Token actualToken = parser.currentToken();
            switch (actualToken) {
                case FIELD_NAME:
                    fieldName = parser.currentName();
                    break;
                case START_ARRAY:
                    list = new ArrayList<>();
                    isList = true;
                    break;
                case VALUE_STRING:
                    if (isList) {
                        list.add(parser.objectText());
                    } else {
                        if (fieldName.equals("id")) {
                            id = parser.objectText().toString();
                        } else {
                            source.put(fieldName, parser.objectText());
                        }
                    }
                    break;
                case VALUE_NUMBER:
                    if (isList) {
                        list.add(parser.numberValue());
                    } else {
                        source.put(fieldName, parser.numberValue());
                    }
                    break;
                case VALUE_NULL:
                    if (isList) {
                        list.add("");
                    } else {
                        source.put(fieldName, "");
                    }
                    break;
                case END_ARRAY:
                    source.put(fieldName, list);
                    list = null;
                    isList = false;
                    break;
                case START_OBJECT:
                    source.put(fieldName, GenericDocument.parse(parser));
                    break;
                default:
                    break;
            }
        }
        log.info("Final of parse genericDocument id: {}, source: {}", id, source);
        return new GenericDocument(id, source);
    }

    /**
     * Builds an GenericDocument XContentBuilder. Iterates over the args map adding key-value pairs
     *
     * @param builder This is received from the parent object
     * @param params Not used
     * @return A complete args XContentBuilder object
     * @throws IOException rethrown from XContentBuilder objects within
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("id", this.id);
        builder.startObject(GenericDocument.SOURCE);
        for (String key : this.source.keySet()) {
            builder.field(key, this.source.get(key));
        }
        builder.endObject();
        return builder.endObject();
    }
}
