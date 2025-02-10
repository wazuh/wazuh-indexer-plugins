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
import org.opensearch.common.UUIDs;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import reactor.util.annotation.NonNull;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

/** Command's fields. */
public class Command implements ToXContentObject {
    public static final String COMMAND = "command";
    public static final String ORDER_ID = "order_id";
    public static final String REQUEST_ID = "request_id";
    public static final String SOURCE = "source";
    public static final String TIMEOUT = "timeout";
    public static final String USER = "user";
    public static final String STATUS = "status";
    private final String orderId;
    private final String requestId;
    private final String source;
    private final Target target;
    private final Integer timeout;
    private final String user;
    private final Status status;
    private final Action action;

    private static final Logger log = LogManager.getLogger(Command.class);

    /**
     * Default constructor
     *
     * @param source origin of the request.
     * @param target {@link Target}
     * @param timeout time window in which the command has to be sent to its target.
     * @param user the user that originated the request
     * @param action {@link Action}
     */
    public Command(
            @NonNull String source,
            @NonNull Target target,
            @NonNull Integer timeout,
            @NonNull String user,
            @NonNull Action action) {
        this.requestId = UUIDs.base64UUID();
        this.orderId = UUIDs.base64UUID();
        this.source = source;
        this.target = target;
        this.user = user;
        this.action = action;
        this.timeout = timeout;
        this.status = Status.PENDING;
    }

    /**
     * Retrieves the timeout value for this command.
     *
     * @return the timeout value in milliseconds.
     */
    public Integer getTimeout() {
        return this.timeout;
    }

    /**
     * Parses the request's payload into the Command model.
     *
     * @param parser XContentParser from the Rest Request
     * @return instance of Command
     * @throws IOException error parsing request content
     * @throws IllegalArgumentException missing arguments
     */
    public static Command parse(XContentParser parser)
            throws IOException, IllegalArgumentException {
        String source = null;
        Target target = null;
        Integer timeout = null;
        String user = null;
        Action action = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                String fieldName = parser.currentName();

                parser.nextToken();
                switch (fieldName) {
                    case SOURCE:
                        source = parser.text();
                        break;
                    case Target.TARGET:
                        target = Target.parse(parser);
                        break;
                    case TIMEOUT:
                        timeout = parser.intValue();
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
        }

        ArrayList<String> nullArguments = new ArrayList<>();
        if (source == null) {
            nullArguments.add("source");
        }
        if (target == null) {
            nullArguments.add("target");
        }
        if (timeout == null) {
            nullArguments.add("timeout");
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
            return new Command(source, target, timeout, user, action);
        }
    }

    /**
     * Parses the request's payload into the Command[] model.
     *
     * @param parser XContentParser from the Rest Request
     * @return instance of Command
     * @throws IOException error parsing request content
     * @throws IllegalArgumentException missing arguments
     */
    public static List<Command> parseToArray(XContentParser parser)
            throws IOException, IllegalArgumentException {
        List<Command> commands = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            Command command = Command.parse(parser);
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
        builder.field(TIMEOUT, timeout);
        builder.field(STATUS, this.status);
        builder.field(ORDER_ID, this.orderId);
        builder.field(REQUEST_ID, this.requestId);

        return builder.endObject();
    }

    /**
     * Parses the content of a RestRequest and retrieves a list of Command objects.
     *
     * @param request the RestRequest containing the command data.
     * @return a list of Command objects parsed from the request content.
     * @throws IOException if an error occurs while parsing the request content.
     */
    public static List<Command> parse(RestRequest request) throws IOException {
        // Request parsing
        XContentParser parser = request.contentParser();
        List<Command> commands = new ArrayList<>();
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        parser.nextToken();
        if (parser.nextToken() == XContentParser.Token.START_ARRAY) {
            commands = Command.parseToArray(parser);
        } else {
            log.error("Token does not match {}", parser.currentToken());
        }

        return commands;
    }

    /**
     * Returns the nested Action fields.
     *
     * @return Action fields.
     */
    public Action getAction() {
        return this.action;
    }

    /**
     * Returns the nested Source fields.
     *
     * @return source fields.
     */
    public String getSource() {
        return this.source;
    }

    /**
     * Returns the nested Target fields.
     *
     * @return Target fields.
     */
    public Target getTarget() {
        return this.target;
    }

    /**
     * Returns the user that requested this command.
     *
     * @return the user that requested this command.
     */
    public String getUser() {
        return this.user;
    }

    @Override
    public String toString() {
        return "Command{"
                + "orderId='"
                + orderId
                + '\''
                + ", requestId='"
                + requestId
                + '\''
                + ", source='"
                + source
                + '\''
                + ", target="
                + target
                + ", timeout="
                + timeout
                + ", user='"
                + user
                + '\''
                + ", status="
                + status
                + ", action="
                + action
                + '}';
    }
}
