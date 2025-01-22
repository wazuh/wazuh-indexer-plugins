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
import org.opensearch.common.time.DateFormatter;
import org.opensearch.common.time.DateUtils;
import org.opensearch.common.time.FormatNames;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.*;
import org.opensearch.search.SearchHit;

import java.io.IOException;
import java.time.ZonedDateTime;

/** Command's target fields. */
public class Order implements ToXContentObject {
    private static final String DATE_FORMAT = FormatNames.DATE_TIME_NO_MILLIS.getSnakeCaseName();
    private static final DateFormatter DATE_FORMATTER = DateFormatter.forPattern(DATE_FORMAT);
    public static final String TIMESTAMP = "@timestamp";
    public static final String DELIVERY_TIMESTAMP = "delivery_timestamp";
    private final Agent agent;
    private final Command command;
    private final String id;
    private final ZonedDateTime timestamp;
    private final ZonedDateTime deliveryTimestamp;

    private static final Logger log = LogManager.getLogger(Order.class);

    /**
     * Default constructor.
     *
     * @param agent "agent" nested fields.
     * @param command "command" nested fields.
     */
    public Order(Agent agent, Command command) {
        this.agent = agent;
        this.command = command;
        this.id = UUIDs.base64UUID();
        this.timestamp = DateUtils.nowWithMillisResolution();
        this.deliveryTimestamp = timestamp.plusSeconds(command.getTimeout());
    }

    /**
     * Parses data from an XContentParser into this model.
     *
     * @param parser xcontent parser.
     * @return initialized instance of Document.
     * @throws IOException parsing error occurred.
     */
    public static Order parse(XContentParser parser) throws IOException {
        Agent agent = null;
        Command command = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            if (fieldName.equals(Command.COMMAND)) {
                command = Command.parse(parser);
            } else if (fieldName.equals(Agent.AGENT)) {
                agent = Agent.parse(parser);
            } else {
                parser.skipChildren(); // TODO raise error as command values are required
            }
        }

        return new Order(agent, command);
    }

    /**
     * Returns the delivery timestamp from a search hit.
     *
     * @param hit search hit parser.
     * @return delivery timestamp from Document in search hit.
     */
    public static ZonedDateTime deliveryTimestampFromSearchHit(SearchHit hit) {
        ZonedDateTime deliveryTimestamp = null;

        try {
            XContentParser parser =
                    XContentHelper.createParser(
                            NamedXContentRegistry.EMPTY,
                            DeprecationHandler.IGNORE_DEPRECATIONS,
                            hit.getSourceRef(),
                            XContentType.JSON);

            parser.nextToken();
            while (parser.nextToken() != null) {
                if (parser.currentToken().equals(XContentParser.Token.FIELD_NAME)) {
                    String fieldName = parser.currentName();
                    if (fieldName.equals(Order.DELIVERY_TIMESTAMP)) {
                        parser.nextToken();
                        deliveryTimestamp = ZonedDateTime.from(DATE_FORMATTER.parse(parser.text()));
                    } else {
                        parser.skipChildren();
                    }
                }
            }

            parser.close();

        } catch (IOException e) {
            log.error("Delivery timestamp could not be parsed: {}", e.getMessage());
        }
        return deliveryTimestamp;
    }

    /**
     * Returns the document's "_id".
     *
     * @return Document's ID
     */
    public String getId() {
        return this.id;
    }

    /**
     * Returns the Command object associated with this Document.
     *
     * @return Command object
     */
    public Command getCommand() {
        return this.command;
    }

    /**
     * Returns the timestamp at which the Command was delivered to the Agent.
     *
     * @return ZonedDateTime object representing the delivery timestamp
     */
    public ZonedDateTime getDeliveryTimestamp() {
        return this.deliveryTimestamp;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        this.agent.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
        this.command.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
        builder.field(TIMESTAMP, DATE_FORMATTER.format(this.timestamp));
        builder.field(DELIVERY_TIMESTAMP, DATE_FORMATTER.format(this.deliveryTimestamp));
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
