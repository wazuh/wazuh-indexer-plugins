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

        XContentParser.Token currentToken = parser.currentToken();
        if (currentToken != XContentParser.Token.START_OBJECT) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to be an object, got [" + parser.currentName() + "]");
        }
        currentToken = parser.nextToken();
        if (currentToken != XContentParser.Token.FIELD_NAME) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to be an object, got [" + currentToken.name() + "]");
        }
        if (!INDEX_KEY.equals(parser.currentName())) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to contain the ["
                            + INDEX_KEY
                            + "] key, got ["
                            + parser.currentName()
                            + "]");
        }
        currentToken = parser.nextToken();
        if (currentToken != XContentParser.Token.VALUE_STRING) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to be a text value, got [" + currentToken.name() + "]");
        }
        args.put(INDEX_KEY, parser.objectText());
        currentToken = parser.nextToken();
        if (currentToken != XContentParser.Token.FIELD_NAME) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to be a field, got [" + currentToken.name() + "]");
        }
        if (!OFFSET_KEY.equals(parser.currentName())) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to contain the ["
                            + OFFSET_KEY
                            + "] key, got ["
                            + parser.currentName()
                            + "]");
        }
        currentToken = parser.nextToken();
        if (currentToken != XContentParser.Token.VALUE_STRING) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to be a text value, got [" + currentToken.name() + "]");
        }
        args.put(OFFSET_KEY, parser.objectText());
        return new Args(args);
    }
}
