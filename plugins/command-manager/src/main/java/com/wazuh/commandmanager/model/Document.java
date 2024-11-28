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
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.List;

/** Command's target fields. */
public class Document implements ToXContentObject {
    private final Agent agent;
    private final Command command;
    private final String id;
    private final long timestamp;
    private final long deliveryTimestamp;

    /**
     * Default constructor
     *
     * @param agent
     * @param command
     */
    public Document(Agent agent, Command command) {
        this.agent = agent;
        this.command = command;
        this.id = UUIDs.base64UUID();
        this.timestamp = System.currentTimeMillis();
        this.deliveryTimestamp = calculateDeliveryTimestamp(this.timestamp, command.getTimeout());
    }

    /**
     * Calculates the delivery timestamp by adding a specified timeout to the given timestamp.
     *
     * @param timestamp the initial timestamp in milliseconds.
     * @param timeout the time in seconds to be added to the timestamp.
     * @return a new timestamp representing the delivery time.
     */
    private long calculateDeliveryTimestamp(long timestamp, int timeout) {
        long timeoutInMillis = timeout * 1000L;
        return timestamp + timeoutInMillis;
    }

    /**
     * @param parser
     * @return
     * @throws IOException
     */
    public static Document parse(XContentParser parser) throws IOException {
        Agent agent = new Agent(List.of("groups000")); // TODO read agent from .agents index
        Command command = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            if (fieldName.equals(Command.COMMAND)) {
                command = Command.parse(parser);
            } else {
                parser.skipChildren(); // TODO raise error as command values are required
            }
        }

        return new Document(agent, command);
    }

    /**
     * @return Document's ID
     */
    public String getId() {
        return this.id;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        this.agent.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
        this.command.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
        builder.field("@timestamp", this.timestamp);
        builder.field("delivery_timestamp", this.deliveryTimestamp);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Document{"
                + "@timestamp="
                + timestamp
                + ", delivery_timestamp="
                + deliveryTimestamp
                + ", agent="
                + agent
                + ", command="
                + command
                + '}';
    }
}
