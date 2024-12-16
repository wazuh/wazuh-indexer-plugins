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
import org.opensearch.common.time.DateFormatter;
import org.opensearch.common.time.DateUtils;
import org.opensearch.common.time.FormatNames;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.List;

/** Command's target fields. */
public class Document implements ToXContentObject {
    private static final String DATE_FORMAT = FormatNames.DATE_TIME_NO_MILLIS.getSnakeCaseName();
    private static final DateFormatter DATE_FORMATTER = DateFormatter.forPattern(DATE_FORMAT);
    public static final String TIMESTAMP = "@timestamp";
    public static final String DELIVERY_TIMESTAMP = "delivery_timestamp";
    private final Agent agent;
    private final Command command;
    private final String id;
    private final ZonedDateTime timestamp;
    private final ZonedDateTime deliveryTimestamp;

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
        this.timestamp = DateUtils.nowWithMillisResolution();
        this.deliveryTimestamp = timestamp.plusSeconds(command.getTimeout());
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
