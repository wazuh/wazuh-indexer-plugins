/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.UUIDs;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import reactor.util.annotation.NonNull;

import java.io.IOException;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

public class Command implements ToXContentObject {
    public static final String NAME = "command";
    public static final String ORDER_ID = "order_id";
    public static final String REQUEST_ID = "request_id";
    public static final String SOURCE = "source";
    public static final String TARGET = "target";
    public static final String TIMEOUT = "timeout";
    public static final String TYPE = "type";
    public static final String USER = "user";
    public static final String STATUS = "status";
    public static final String ACTION = "action";
    private final String id;
    private final String orderId;
    private final String requestId;
    private final String source;
    private final String target;
    private final Integer timeout;
    private final String type;
    private final String user;
    private final Status status;
    private final Action action;

    /**
     * Default constructor
     *
     * @param source  origin of the request. One
     * @param target  Cluster name destination.
     * @param timeout Number of seconds to wait for the command to be executed.
     * @param type    action type. One of agent_groups, agent, server.
     * @param user    the user that originated the request
     * @param action  target action type and additional parameters
     */
    public Command(
            @NonNull String source,
            @NonNull String target,
            @NonNull Integer timeout,
            @NonNull String type,
            @NonNull String user,
            @NonNull Action action
    ) {
        this.id = UUIDs.base64UUID();
        this.requestId = UUIDs.base64UUID();
        this.orderId = UUIDs.base64UUID();
        this.source = source;
        this.target = target;
        this.timeout = timeout;
        this.type = type;
        this.user = user;
        this.action = action;
        this.status = Status.PENDING;
    }

    /**
     * Parses the request's payload into the Command model.
     *
     * @param parser XContentParser from the Rest Request
     * @return instance of Command
     * @throws IOException
     */
    public static Command parse(XContentParser parser) throws IOException {
        String source = null;
        String target = null;
        Integer timeout = null;
        String type = null;
        String user = null;
        Action action = null;

        // skips JSON's root level "command"
        ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser);
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();

            parser.nextToken();
            switch (fieldName) {
                case SOURCE:
                    source = parser.text();
                    break;
                case TARGET:
                    target = parser.text();
                    break;
                case TIMEOUT:
                    timeout = parser.intValue();
                    break;
                case TYPE:
                    type = parser.text();
                    break;
                case USER:
                    user = parser.text();
                    break;
                case ACTION:
                    action = Action.parse(parser);
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }

        assert source != null;
        assert target != null;
        assert timeout != null;
        return new Command(
                source,
                target,
                timeout,
                type,
                user,
                action
        );
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        builder.startObject(NAME);
        builder.field(SOURCE, this.source);
        builder.field(USER, this.user);
        builder.field(TARGET, this.target);
        builder.field(TYPE, this.type);
        this.action.toXContent(builder, ToXContent.EMPTY_PARAMS);
        builder.field(TIMEOUT, timeout);
        builder.field(STATUS, this.status);
        builder.field(ORDER_ID, this.orderId);
        builder.field(REQUEST_ID, this.requestId);
        builder.endObject();

        return builder.endObject();
    }

    /**
     * @return Document's ID
     */
    public String getId() {
        return this.id;
    }

    @Override
    public String toString() {
        return "Command{" +
                "ID='" + id + '\'' +
                ", orderID='" + orderId + '\'' +
                ", requestID='" + requestId + '\'' +
                ", source='" + source + '\'' +
                ", target='" + target + '\'' +
                ", timeout=" + timeout +
                ", type='" + type + '\'' +
                ", user='" + user + '\'' +
                ", status=" + status +
                ", action=" + action +
                '}';
    }
}
