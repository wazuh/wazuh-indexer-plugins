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

import org.opensearch.core.common.ParsingException;
import org.opensearch.core.xcontent.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** ToXContentObject model to parse and build CTI API changes query replies. */
public class ContentChanges implements ToXContentObject {

    private static final String DATA = "data";

    private final List<Offset> changes;

    /**
     * Constructor method
     *
     * @param changes a List of CVEChange objects, each containing a JSON patch.
     */
    public ContentChanges(List<Offset> changes) {
        this.changes = changes;
    }

    /**
     * Retrieve the list of CVE changes
     *
     * @return A list of CVEChange objects
     */
    public List<Offset> getChangesList() {
        return this.changes;
    }

    /**
     * Parses the data[] object from the CTI API changes response body
     *
     * @param parser The received parser object
     * @return a ContentChanges object with all inner array values parsed.
     * @throws IOException rethrown from the inner parse() methods
     * @throws IllegalArgumentException rethrown from the inner parse() methods
     * @throws ParsingException rethrown from ensureExpectedToken()
     */
    public static ContentChanges parse(XContentParser parser)
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
        // Iterate over the array and add each CVEChange object to changes list
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            changes.add(Offset.parse(parser));
        }
        return new ContentChanges(changes);
    }

    /**
     * Outputs an XContentBuilder object ready to be printed or manipulated
     *
     * @param builder the received builder object
     * @param params Unused params
     * @return an XContentBuilder object ready to be printed
     * @throws IOException rethrown from CVEChange's toXContent
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startArray(DATA);
        // For each CVEChange in the data field, add them to an XContentBuilder array
        changes.forEach(
                (change) -> {
                    try {
                        change.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
        builder.endArray();
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "ContentChanges{" + "changes=" + changes + '}';
    }
}
