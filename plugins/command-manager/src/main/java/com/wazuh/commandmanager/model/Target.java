/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
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
