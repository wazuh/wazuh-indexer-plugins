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
package com.wazuh.contentmanager.cti.catalog.model;

import org.opensearch.core.common.ParsingException;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** ToXContentObject model to parse and build CTI API changes query replies. */
public class Changes implements ToXContentObject {
    private static final String JSON_DATA_KEY = "data";
    private final ArrayList<Offset> list;

    /** Constructor. */
    public Changes() {
        this.list = new ArrayList<>();
    }

    /**
     * Constructor.
     *
     * @param list a List of Offset objects, each containing a JSON patch.
     */
    public Changes(List<Offset> list) {
        this.list = new ArrayList<>(list);
    }

    /**
     * Get the list of changes.
     *
     * @return A list of Offset objects
     */
    public ArrayList<Offset> get() {
        return this.list;
    }

    /**
     * Get first element of the changes list.
     *
     * @return first {@link Offset} element in the list, or null.
     */
    public Offset getFirst() {
        return !this.list.isEmpty() ? this.list.get(0) : null;
    }

    /**
     * Get last element of the changes list.
     *
     * @return last {@link Offset} element in the list, or null.
     */
    public Offset getLast() {
        return !this.list.isEmpty() ? this.list.get(this.list.size() - 1) : null;
    }

    /**
     * Parses the data[] object from the CTI API changes response body.
     *
     * @param parser The received parser object.
     * @return a ContentChanges object with all inner array values parsed.
     * @throws IOException rethrown from the inner parse() methods.
     * @throws IllegalArgumentException rethrown from the inner parse() methods.
     * @throws ParsingException rethrown from ensureExpectedToken().
     */
    public static Changes parse(XContentParser parser)
            throws IOException, IllegalArgumentException, ParsingException {
        List<Offset> changes = new ArrayList<>();
        // Make sure we are at the start
        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        // Check that we are indeed reading the "data" array
        XContentParserUtils.ensureFieldName(parser, parser.nextToken(), JSON_DATA_KEY);
        // Check we are at the start of the array
        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_ARRAY, parser.nextToken(), parser);
        // Iterate over the array and add each Offset object to changes list
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            changes.add(Offset.parse(parser));
        }
        return new Changes(changes);
    }

    /**
     * Outputs an XContentBuilder object ready to be printed or manipulated
     *
     * @param builder the received builder object
     * @param params Unused params
     * @return an XContentBuilder object ready to be printed
     * @throws IOException rethrown from Offset's toXContent
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startArray(Changes.JSON_DATA_KEY);
        // For each Offset in the data field, add them to an XContentBuilder array
        for (Offset change : this.list) {
            change.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
        }
        builder.endArray();
        return builder.endObject();
    }
}
