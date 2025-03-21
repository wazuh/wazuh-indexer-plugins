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
package com.wazuh.commandmanager.model;

import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class UpdateContentCommand extends Args {

    public static final String INDEX_KEY = "index";
    public static final String OFFSET_KEY = "offset";

    /**
     * Dedicated command.action.args parser for "update" action type.
     *
     * @param parser An XContentParser containing an args to be deserialized
     * @return An Args object
     * @throws IOException Rethrows the exception from list() and objectText() method
     */
    public static Args parse(XContentParser parser) throws IOException {
        Map<String, Object> args = new HashMap<>();
        boolean indexParsed = false;
        boolean offsetParsed = false;
        String fieldName = "";

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParser.Token actualToken = parser.currentToken();
            switch (actualToken) {
                case FIELD_NAME:
                    fieldName = parser.currentName();
                    switch (fieldName) {
                        case INDEX_KEY:
                            indexParsed = true;
                            break;
                        case OFFSET_KEY:
                            offsetParsed = true;
                            break;
                        default:
                            throw new IllegalArgumentException(
                                    "Expected [command.action.args] to contains only the ["
                                            + INDEX_KEY
                                            + "] and ["
                                            + OFFSET_KEY
                                            + "] keys, got ["
                                            + parser.currentName()
                                            + "]");
                    }
                    break;
                case VALUE_STRING:
                    args.put(fieldName, parser.objectText());
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Expected [command.action.args] to be an field or a text value, got ["
                                    + parser.currentName()
                                    + "]");
            }
        }

        if (indexParsed && offsetParsed) {
            return new Args(args);
        } else {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to contain the ["
                            + INDEX_KEY
                            + "] and ["
                            + OFFSET_KEY
                            + "] keys");
        }
    }
}
