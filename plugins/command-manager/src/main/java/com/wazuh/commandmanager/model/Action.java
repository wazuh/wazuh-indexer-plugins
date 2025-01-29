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
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.Locale;

import reactor.util.annotation.NonNull;
import reactor.util.annotation.Nullable;

/** Command's action fields. */
public class Action implements ToXContentObject {
    public static final String ACTION = "action";
    public static final String NAME = "name";
    public static final String VERSION = "version";
    private final String name;
    private final Args args;
    private final String version;

    private static final Logger log = LogManager.getLogger(Action.class);

    /**
     * Default constructor.
     *
     * @param name action to be executed on the target,
     * @param args actual command.
     * @param version version of the action.
     */
    public Action(@NonNull String name, @Nullable Args args, String version) {
        this.name = name;
        this.args = args;
        this.version = version;
    }

    /**
     * Parses data from an XContentParser into this model.
     *
     * @param parser xcontent parser.
     * @return initialized instance of Action.
     * @throws IOException parsing error occurred.
     */
    public static Action parse(XContentParser parser) throws IOException {
        String name = "";
        Args args = new Args();
        String version = "";

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            switch (fieldName) {
                case NAME:
                    name = parser.text();
                    break;
                case Args.ARGS:
                    try {
                        log.info("NAME: {}", name);
                        // Convert the action name to uppercase and replace hyphens with underscores
                        // to match the enum constants.
                        ActionName actionName =
                                ActionName.valueOf(name.toUpperCase(Locale.ROOT).replace("-", "_"));
                        switch (actionName) {
                            case SET_GROUP:
                                log.info("Parsing arguments for [set-group] command");
                                try {
                                    args = SetGroupCommand.parse(parser);
                                } catch (IllegalArgumentException e) {
                                    log.error("Error parsing action {}", e.getMessage());
                                    throw new IOException(e);
                                }
                                break;
                            case FETCH_CONFIG:
                                log.info("Parsing arguments for [fetch-config] command");
                                args = FetchConfigCommand.parse(parser);
                                break;
                        }
                    } catch (IllegalArgumentException e) {
                        log.info("Parsing arguments for [generic] command");
                        args = Args.parse(parser);
                    }
                    break;
                case VERSION:
                    version = parser.text();
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }

        return new Action(name, args, version);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(ACTION);
        builder.field(NAME, this.name);
        if (this.args != null) {
            this.args.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
        }
        builder.field(VERSION, this.version);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Action{"
                + "name='"
                + this.name
                + '\''
                + ", args="
                + this.args
                + ", version='"
                + this.version
                + '\''
                + '}';
    }
}
