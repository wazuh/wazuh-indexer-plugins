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

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

/** Command's target fields. */
public class Target implements ToXContentObject {
    public static final String TARGET = "target";
    public static final String TYPE = "type";
    public static final String ID = "id";

    // Define the enum for type
    public enum Type {
        AGENT("agent"),
        GROUP("group");

        private final String value;

        Type(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public static Type fromString(String value) {
            for (Type type : Type.values()) {
                if (type.value.equalsIgnoreCase(value)) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid type: " + value);
        }
    }

    private final Type type;
    private final String id;

    /**
     * Default constructor.
     *
     * @param type The destination type. One of [`group`, `agent`, `server`]
     * @param id Unique identifier of the destination to send the command to.
     */
    public Target(Type type, String id) {
        this.type = type;
        this.id = id;
    }

    /**
     * Retrieves the id of this target.
     *
     * @return the target's id.
     */
    public String getId() {
        return this.id;
    }

    /**
     * Retrieves the type of this target.
     *
     * @return the target's type.
     */
    public Type getType() {
        return this.type;
    }

    /**
     * Parses data from an XContentParser into this model.
     *
     * @param parser xcontent parser.
     * @return initialized instance of Target.
     * @throws IOException parsing error occurred.
     */
    public static Target parse(XContentParser parser) throws IOException {
        Type type = null;
        String id = "";

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            switch (fieldName) {
                case TYPE:
                    type = Type.fromString(parser.text());
                    break;
                case ID:
                    id = parser.text();
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }

        return new Target(type, id);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(TARGET);
        builder.field(TYPE, this.type.getValue());
        builder.field(ID, this.id);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Target{" + "type='" + type.getValue() + '\'' + ", id='" + id + '\'' + '}';
    }
}
