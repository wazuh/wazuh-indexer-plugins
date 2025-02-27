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

public class SetGroupCommand extends Args {
    private static final Logger log = LogManager.getLogger(SetGroupCommand.class);

    public static final String GROUPS_KEY = "groups";

    public static Args validate(Args args) throws IllegalArgumentException {
        Map<String, Object> argsMap = args.getArgs();
        ArrayList<String> groups = null;
        for (String field : argsMap.keySet()) {
            if (field.equals(GROUPS_KEY)) {
                try {
                    groups = (ArrayList<String>) argsMap.get(GROUPS_KEY);
                } catch (Exception e) {
                    throw new IllegalArgumentException(
                            "Expected [command.action.args.groups] to be an array of strings only. "
                                    + e.getMessage());
                }
            } else {
                throw new IllegalArgumentException(
                        "Expected [command.action.args] to contain only the [groups] key, got [" + field + "]");
            }
        }

        if (groups == null) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args.groups] exists in [command.action.args].");
        }
        return args;
    }

    /**
     * Dedicated command.action.args parser for "set-group" action type.
     *
     * @param parser An XContentParser containing an args to be deserialized
     * @return An Args object
     * @throws IOException Rethrows the exception from list() and objectText() method
     */
    public static Args parse(XContentParser parser) throws IOException {
        Map<String, Object> args = new HashMap<>();
        List<String> groupList = new ArrayList<>();

        // Parser currently on "args" key. Next expected token is START_OBJECT.
        XContentParser.Token currentToken = parser.currentToken();
        if (currentToken != XContentParser.Token.START_OBJECT) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to be an object, got [" + parser.currentName() + "]");
        }
        // Next expected token is "groups" key, followed by an array of strings only.
        currentToken = parser.nextToken();
        if (currentToken != XContentParser.Token.FIELD_NAME) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to be an object, got [" + currentToken.name() + "]");
        }
        if (!GROUPS_KEY.equals(parser.currentName())) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args] to contain the [groups] key, got ["
                            + parser.currentName()
                            + "]");
        }
        // Next expected token is START_ARRAY.
        currentToken = parser.nextToken();
        if (currentToken != XContentParser.Token.START_ARRAY) {
            throw new IllegalArgumentException(
                    "Expected [command.action.args.groups] to be an array, got ["
                            + currentToken.name()
                            + "]");
        }
        // Iterate until token is END_ARRAY.
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            currentToken = parser.currentToken();

            if (currentToken != XContentParser.Token.VALUE_STRING) {
                throw new IllegalArgumentException(
                        "Expected [command.action.args.groups] to be an array of strings only, got ["
                                + currentToken.name()
                                + "]");
            }
            groupList.add(parser.text());
        }
        // Consume the END_OBJECT token
        parser.nextToken();

        args.put(GROUPS_KEY, groupList);
        return new Args(args);
    }
}
