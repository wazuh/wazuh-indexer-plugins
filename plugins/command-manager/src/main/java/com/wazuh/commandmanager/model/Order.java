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
import org.opensearch.core.xcontent.*;

import java.io.IOException;

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
    private final String documentId;

    private static final Logger log = LogManager.getLogger(Order.class);

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
            @NonNull Action action,
            @NonNull String documentId) {
        this.source = source;
        this.target = target;
        this.user = user;
        this.action = action;
        this.documentId = documentId;
    }

    public static Order parse(XContentParser parser, String documentId)
    {
        try {
            Command command = null;
            // Iterate over the JsonXContentParser's JsonToken until we hit null,
            // which corresponds to end of data
            while (parser.nextToken() != null) {
                // Look for FIELD_NAME JsonToken s
                if (!parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                   continue;
                }
                String fieldName = parser.currentName();
                if (fieldName.equals(Command.COMMAND)) {
                    // Parse Command
                    command = Command.parse(parser);
                } else {
                    parser.skipChildren();
                }
            }
            // Create a new Order object with the Command's fields
            assert command != null;
            return new Order(
                command.getSource(),
                command.getTarget(),
                command.getUser(),
                command.getAction(),
                documentId
            );
        } catch (IOException e) {
            log.error("Order could not be parsed: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params)
            throws IOException {
        builder.startObject();
        builder.field(SOURCE, this.source);
        builder.field(USER, this.user);
        this.target.toXContent(builder, ToXContent.EMPTY_PARAMS);
        this.action.toXContent(builder, ToXContent.EMPTY_PARAMS);
        builder.field(DOCUMENT_ID, this.documentId);

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
                + documentId
                + '\''
                + '}';
    }
}
