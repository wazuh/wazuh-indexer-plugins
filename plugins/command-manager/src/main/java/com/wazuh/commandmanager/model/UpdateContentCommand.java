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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class UpdateContentCommand extends Args {
    private static final Logger log = LogManager.getLogger(UpdateContentCommand.class);

    private static final String INDEX_KEY = "index";
    private static final String OFFSET_KEY = "offset";
    private static final String INVALID_ARGS_MESSAGE =
            "Expected [command.action.args] to contain the ["
                    + INDEX_KEY
                    + "] and ["
                    + OFFSET_KEY
                    + "] keys";

    /**
     * Dedicated command.action.args parser for "update" action type.
     *
     * @param parser An XContentParser containing an args to be deserialized
     * @return An Args object
     * @throws IOException Rethrows the exception from list() and objectText() method
     */
    public static Args parse(XContentParser parser) throws IOException {
        Map<String, Object> args = new HashMap<>();
        String fieldName = "";

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParser.Token currentToken = parser.currentToken();
            switch (currentToken) {
                case FIELD_NAME:
                    fieldName = parser.currentName();
                    if (!fieldName.equals(INDEX_KEY) && !fieldName.equals(OFFSET_KEY)) {
                        log.warn(INVALID_ARGS_MESSAGE + ", got [{}]", parser.currentName());
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

        if (args.containsKey(INDEX_KEY) && args.containsKey(OFFSET_KEY)) {
            return new Args(args);
        }
        throw new IllegalArgumentException(INVALID_ARGS_MESSAGE);
    }
}
