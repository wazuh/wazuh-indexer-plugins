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

import org.opensearch.common.UUIDs;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import reactor.util.annotation.NonNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Order implements ToXContentObject {
    public static final String COMMAND = "command";
    public static final String SOURCE = "source";
    public static final String USER = "user";
    private final String source;
    private final Target target;
    private final String user;
    private final Action action;

    /**
     * Default constructor
     *
     * @param source origin of the request.
     * @param target {@link Target}
     * @param user the user that originated the request
     * @param action {@link Action}
     */
    public Order(
            @NonNull String source,
            @NonNull Target target,
            @NonNull String user,
            @NonNull Action action) {
        this.source = source;
        this.target = target;
        this.user = user;
        this.action = action;
    }

    /**
     * Parses the request's payload into the Command model.
     *
     * @param parser XContentParser from the Rest Request
     * @return instance of Command
     * @throws IOException error parsing request content
     * @throws IllegalArgumentException missing arguments
     */
    public static Order parse(XContentParser parser)
            throws IOException, IllegalArgumentException {
        String source = null;
        Target target = null;
        String user = null;
        Action action = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();

            parser.nextToken();
            switch (fieldName) {
                case SOURCE:
                    source = parser.text();
                    break;
                case Target.TARGET:
                    target = Target.parse(parser);
                    break;
                case USER:
                    user = parser.text();
                    break;
                case Action.ACTION:
                    action = Action.parse(parser);
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }

        ArrayList<String> nullArguments = new ArrayList<>();
        if (source == null) {
            nullArguments.add("source");
        }
        if (target == null) {
            nullArguments.add("target");
        }
        if (user == null) {
            nullArguments.add("user");
        }
        if (action == null) {
            nullArguments.add("action");
        }

        if (!nullArguments.isEmpty()) {
            throw new IllegalArgumentException("Missing arguments: " + nullArguments);
        } else {
            return new Order(source, target, user, action);
        }
    }

    public static List<Order> parseToArray(XContentParser parser)
            throws IOException, IllegalArgumentException {
        List<Order> commands = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            Order command = Order.parse(parser);
            commands.add(command);
        }
        return commands;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(COMMAND);
        builder.field(SOURCE, this.source);
        builder.field(USER, this.user);
        this.target.toXContent(builder, ToXContent.EMPTY_PARAMS);
        this.action.toXContent(builder, ToXContent.EMPTY_PARAMS);

        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Order{" +
            "action=" + action +
            ", source='" + source + '\'' +
            ", target=" + target +
            ", user='" + user + '\'' +
            '}';
    }
}
