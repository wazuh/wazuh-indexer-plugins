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
    private final String type;
    private final String id;

    /**
     * Default constructor.
     *
     * @param type The destination type. One of [`group`, `agent`, `server`]
     * @param id Unique identifier of the destination to send the command to.
     */
    public Target(String type, String id) {
        this.type = type;
        this.id = id;
    }

    /**
     * @param parser
     * @return
     * @throws IOException
     */
    public static Target parse(XContentParser parser) throws IOException {
        String type = "";
        String id = "";

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            switch (fieldName) {
                case TYPE:
                    type = parser.text();
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
        builder.field(TYPE, this.type);
        builder.field(ID, this.id);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Target{" + "type='" + type + '\'' + ", id='" + id + '\'' + '}';
    }
}
