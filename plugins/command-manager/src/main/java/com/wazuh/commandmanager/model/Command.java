/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.model;

import org.opensearch.common.UUIDs;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;

import reactor.util.annotation.NonNull;

public class Command implements ToXContentObject {
    public static final String COMMAND = "command";
    public static final String ORDER_ID = "order_id";
    public static final String REQUEST_ID = "request_id";
    public static final String SOURCE = "source";
    public static final String TIMEOUT = "timeout";
    public static final String USER = "user";
    public static final String STATUS = "status";
    public static final String TIMESTAMP = "@timestamp";
    public static final String DELIVERY_TIMESTAMP = "delivery_timestamp";
    private final String orderId;
    private final String requestId;
    private final String source;
    private final Target target;
    private final Integer timeout;
    private final String user;
    private final Status status;
    private final Action action;
    private final Timestamp timestamp;
    private final Timestamp deliveryTimestamp;

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
        this.timeout = timeout;
        this.user = user;
        this.action = action;
        this.status = Status.PENDING;
        this.timestamp = new Timestamp(System.currentTimeMillis());
        this.deliveryTimestamp = calculateDeliveryTimestamp(this.timestamp, this.timeout);
    }

    /**
     * Calculates the delivery timestamp by adding a specified timeout to the given timestamp.
     *
     * @param timestamp the initial timestamp to which the timeout will be added.
     * @param timeout the time in seconds to be added to the timestamp.
     * @return a new {@link Timestamp} representing the delivery time.
     */
    private Timestamp calculateDeliveryTimestamp(Timestamp timestamp, int timeout) {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(timestamp.getTime());
        cal.add(Calendar.SECOND, timeout);
        return new Timestamp(cal.getTimeInMillis());
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
        builder.field(TIMESTAMP, this.timestamp);
        builder.field(DELIVERY_TIMESTAMP, this.deliveryTimestamp);

        return builder.endObject();
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
                + ", @timestamp='"
                + timestamp
                + '\''
                + ", delivery_timestamp='"
                + deliveryTimestamp
                + '\''
                + '}';
    }
}
