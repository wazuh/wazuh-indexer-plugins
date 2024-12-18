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

import com.wazuh.commandmanager.index.CommandIndex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.xcontent.*;

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
            @NonNull Action action) {
        this.source = source;
        this.target = target;
        this.user = user;
        this.action = action;
    }

    public void setDocumentId(String documentId) {
        this.document_id = documentId;
    }

    public static Order parse(XContentParser parser)
    {
        try {
            Command command = null;
            while (parser.nextToken() != null) {
                if (!parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                   continue;
                }
                String fieldName = parser.currentName();
                if (fieldName.equals(Command.COMMAND)) {
                    command = Command.parse(parser);
                } else {
                    parser.skipChildren();
                }
            }
            log.debug("Creating new Order Object");
            assert command != null;
            return new Order(
                command.getSource(),
                command.getTarget(),
                command.getUser(),
                command.getAction()
            );
        } catch (Exception e) {
            e.printStackTrace();
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
