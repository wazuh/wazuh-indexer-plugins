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
package com.wazuh.contentmanager.model.cti;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;

/**
 * Class representing a JSON Patch operation.
 *
 * <p>This class implements the ToXContentObject interface, allowing it to be serialized to XContent
 * format. It is used to define operations that can be applied to a JSON document, such as adding,
 * removing, or replacing elements.
 */
public class PatchOperation implements ToXContentObject {
    public static final String OP = "op";
    public static final String PATH = "path";
    public static final String FROM = "from";
    public static final String VALUE = "value";
    private final String op;
    private final String path;
    private final String from;
    private final String value;

    private static final Logger log = LogManager.getLogger(PatchOperation.class);

    /**
     * Constructor.
     *
     * @param op Operation type (add, remove, replace).
     * @param path Path to the element to be modified.
     * @param from Source path for move operations.
     * @param value Value to be added or replaced.
     */
    public PatchOperation(String op, String path, String from, String value) {
        this.op = op;
        this.path = path;
        this.from = from;
        this.value = value;
    }

    /**
     * Parses a JSON object to create a PatchOperation instance.
     *
     * @param parser The XContentParser to parse the JSON object.
     * @return A PatchOperation instance.
     * @throws IllegalArgumentException if the JSON object is invalid.
     * @throws IOException if an I/O error occurs during parsing.
     */
    public static PatchOperation parse(XContentParser parser)
            throws IllegalArgumentException, IOException {
        String op = null;
        String path = null;
        String from = null;
        String value = null;

        // Make sure we are at the start
        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        // Iterate over the object and add each Offset object to changes array
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName(); // Get key
            parser.nextToken(); // Move to value
            switch (fieldName) {
                case OP:
                    op = parser.text();
                    break;
                case PATH:
                    path = parser.text();
                    break;
                case FROM:
                    from = parser.text();
                    break;
                case VALUE:
                    value = parser.text();
                    break;
                default:
                    log.error("Unknown field [{}] parsing a JSON Patch operation", fieldName);
                    break;
            }
        }

        return new PatchOperation(op, path, from, value);
    }

    /**
     * Outputs an XContentBuilder object ready to be printed or manipulated
     *
     * @param builder the received builder object
     * @param params We don't really use this one
     * @return an XContentBuilder object ready to be printed
     * @throws IOException rethrown from Offset's toXContent
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(OP, this.op);
        builder.field(PATH, this.path);
        if (this.from != null) {
            builder.field(FROM, this.from);
        }
        if (this.value != null) {
            builder.field(VALUE, this.value);
        }
        return builder.endObject();
    }
}
