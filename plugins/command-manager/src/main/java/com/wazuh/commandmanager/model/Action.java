/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.model;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.List;

/** Command's action fields. */
public class Action implements ToXContentObject {
    public static final String ACTION = "action";
    public static final String NAME = "name";
    public static final String ARGS = "args";
    public static final String VERSION = "version";
    private final String name;
    private final List<String> args;
    private final String version;

    /**
     * Default constructor.
     *
     * @param name action to be executed on the target,
     * @param args actual command.
     * @param version version of the action.
     */
    public Action(String name, List<String> args, String version) {
        this.name = name;
        this.args = args;
        this.version = version;
    }

    /**
     * @param parser
     * @return
     * @throws IOException
     */
    public static Action parse(XContentParser parser) throws IOException {
        String name = "";
        List<Object> args = List.of();
        String version = "";

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            switch (fieldName) {
                case NAME:
                    name = parser.text();
                    break;
                case ARGS:
                    args = parser.list();
                    break;
                case VERSION:
                    version = parser.text();
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }

        // Cast args field Object list to String list
        List<String> convertedArgsFields = (List<String>) (List<?>) (args);
        return new Action(name, convertedArgsFields, version);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(ACTION);
        builder.field(NAME, this.name);
        builder.field(ARGS, this.args);
        builder.field(VERSION, this.version);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Action{"
                + "name='"
                + name
                + '\''
                + ", args="
                + args
                + ", version='"
                + version
                + '\''
                + '}';
    }
}
