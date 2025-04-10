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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a command to refresh indices in the system. This class extends
 * Args and provides a parser specifically for the "refresh" action type.
 */
public class RefreshCommand extends Args {
    private static final Logger log = LogManager.getLogger(RefreshCommand.class);

    private static final String INDEX_KEY = "index";
    private static final String INVALID_ARGS_MESSAGE =
        "Expected [command.action.args] to contain the [" + INDEX_KEY + "] key";

    /**
     * Dedicated command.action.args parser for "refresh" action type.
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
                    break;

                case VALUE_STRING:
                    if (INDEX_KEY.equals(fieldName)) {
                        List<String> indices = new ArrayList<>();
                        indices.add(parser.text());
                        args.put(INDEX_KEY, indices);
                    } else {
                        log.warn(INVALID_ARGS_MESSAGE + ", got [{}]", parser.currentName());
                    }
                    break;

                case START_ARRAY:
                    if (INDEX_KEY.equals(fieldName)) {
                        List<String> indices = new ArrayList<>();
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            if (parser.currentToken() != XContentParser.Token.VALUE_STRING) {
                                throw new IllegalArgumentException("Index must be a string value");
                            }
                            indices.add(parser.text());
                        }
                        args.put(INDEX_KEY, indices);
                    } else {
                        log.warn(INVALID_ARGS_MESSAGE + ", got [{}]", parser.currentName());
                    }
                    break;

                default:
                    throw new IllegalArgumentException(
                        "Expected [command.action.args] to be a field or a text value, got ["
                            + parser.currentName() + "]");
            }
        }
        return new Args(args);
    }
}
