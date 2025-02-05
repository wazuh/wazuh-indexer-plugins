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
package com.wazuh.contentmanager.model.ctiapi;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.ParsingException;
import org.opensearch.core.xcontent.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * ToXContentObject model to parse and build CTI API changes query replies.
 */
public class Offsets implements ToXContentObject {

    private static final Logger log = LogManager.getLogger(Offsets.class);
    private static final String DATA = "data";

    private final List<Offset> offsetList;

    /**
     * Constructor method
     * @param offsetList a List of the Offset objects, containing a json patch each.
     */
    public Offsets(List<Offset> offsetList) {
        this.offsetList = offsetList;
    }

    /**
     * Parses the data[] object from the CTI API changes response body
     * @param parser The received parser object
     * @return an Offsets object with all inner array values parsed.
     * @throws IOException rethrown from the inner parse() methods
     * @throws IllegalArgumentException rethrown from the inner parse() methods
     * @throws ParsingException rethrown from ensureExpectedToken()
     */
    public static Offsets parse(XContentParser parser)
            throws IOException, IllegalArgumentException, ParsingException {
        List<Offset> changes = new ArrayList<>();
        // Make sure we are at the start
        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        // Check that we are indeed reading the "data" array
        XContentParserUtils.ensureFieldName(parser, parser.nextToken(), DATA);
        // Check we are at the start of the array
        XContentParserUtils.ensureExpectedToken(
            XContentParser.Token.START_ARRAY, parser.nextToken(), parser);
        // Iterate over the array and add each Offset object to changes array
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            changes.add(Offset.parse(parser));
        }
        return new Offsets(changes);
    }

    /**
     * Outputs an XContentBuilder object ready to be printed or manipulated
     * @param builder the received builder object
     * @param params We don't really use this one
     * @return an XContentBuilder object ready to be printed
     * @throws IOException rethrown from Offset's toXContent
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startArray(DATA);
        // For each Offset in the data field, add them to an XContentBuilder array
        offsetList.forEach(
                (offset) -> {
                    try {
                        offset.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
        builder.endArray();
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Offsets{" +
            "offsets=" + offsetList +
            '}';
    }
}
