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

public class UpdateTarget extends Target {

    public static final String UPDATE_TYPE = "server";
    public static final String UPDATE_ID = "vulnerability-detector";

    /**
     * Default constructor.
     *
     * @param type The destination type. One of [`group`, `agent`, `server`]
     * @param id Unique identifier of the destination to send the command to.
     */
    public UpdateTarget(Type type, String id) {
        super(type, id);
    }

    public static Target parse(XContentParser parser) throws IOException {
        String fieldName = "";
        Type type = null;
        String id = "";

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParser.Token actualToken = parser.currentToken();
            switch (actualToken) {
                case FIELD_NAME:
                    if (parser.currentName().equals(Target.TYPE) || parser.currentName().equals(Target.ID)) {
                        fieldName = parser.currentName();
                    } else {
                        throw new IllegalArgumentException(
                                "Expected [command.target] to contains only the ["
                                        + Target.TYPE
                                        + "] and ["
                                        + Target.ID
                                        + "] keys, got ["
                                        + parser.currentName()
                                        + "]");
                    }
                    break;
                case VALUE_STRING:
                    switch (fieldName) {
                        case Target.TYPE:
                            if (parser.text().equals(UPDATE_TYPE)) {
                                type = Type.fromString(parser.text());
                            } else {
                                throw new IllegalArgumentException(
                                        "Expected [command.target.type] to contain ["
                                                + UPDATE_TYPE
                                                + "] value, got ["
                                                + parser.text()
                                                + "]");
                            }
                            break;
                        case Target.ID:
                            if (parser.text().equals(UPDATE_ID)) {
                                id = parser.text();
                            } else {
                                throw new IllegalArgumentException(
                                        "Expected [command.target.id] to contain ["
                                                + UPDATE_ID
                                                + "] value, got ["
                                                + parser.text()
                                                + "]");
                            }
                            break;
                    }
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Expected [command.target] to contains only the ["
                                    + Target.TYPE
                                    + "] and ["
                                    + Target.ID
                                    + "] keys, got ["
                                    + parser.currentName()
                                    + "]");
            }
        }
        return new Target(type, id);
    }
}
