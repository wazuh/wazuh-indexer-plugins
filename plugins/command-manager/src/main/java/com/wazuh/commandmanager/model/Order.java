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

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;

import reactor.util.annotation.NonNull;

public class Order implements ToXContent {
    public static final String ORDERS = "orders";
    public static final String SOURCE = "source";
    public static final String USER = "user";
    public static final String DOCUMENT_ID = "document_id";
    private final String source;
    private final Target target;
    private final String user;
    private final Action action;
    private String document_id;

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

    public void setDocumentId(String documentId) {
        this.document_id = documentId;
    }

    /**
     * Parses the request's payload into the Command model.
     *
     * @param parser XContentParser from the Rest Request
     * @return instance of Command
     * @throws IOException error parsing request content
     * @throws IllegalArgumentException missing arguments
     */
    public static Order parse(XContentParser parser) throws IOException, IllegalArgumentException {
        String source = null;
        Target target = null;
        String user = null;
        Action action = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();

            parser.nextToken();
            switch (fieldName) {
                    // If we find an Order nested below
                    // a Command object, parse the Order recursively
                    // and return its output
                case Command.COMMAND:
                    return Order.parse(parser);
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

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params)
            throws IOException {
        builder.startObject();
        builder.field(SOURCE, this.source);
        builder.field(USER, this.user);
        this.target.toXContent(builder, ToXContent.EMPTY_PARAMS);
        this.action.toXContent(builder, ToXContent.EMPTY_PARAMS);
        builder.field(DOCUMENT_ID, this.document_id);

        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Order{"
                + "action="
                + action
                + ", source='"
                + source
                + '\''
                + ", target="
                + target
                + ", user='"
                + user
                + '\''
                + ", document_id='"
                + document_id
                + '\''
                + '}';
    }
}
