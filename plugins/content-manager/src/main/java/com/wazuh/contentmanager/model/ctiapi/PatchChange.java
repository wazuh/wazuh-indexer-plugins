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
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.wazuh.contentmanager.model.ctiapi.ConsumerInfo.DATA;

public class PatchChange implements ToXContentObject {

    private static final String CONTEXT = "context";
    private static final String OFFSET = "offset";
    private static final String RESOURCE = "resource";
    private static final String TYPE = "type";
    private static final String VERSION = "version";
    private static final String OPERATIONS = "operations";
    private final String context;
    private final Long offset;
    private final String resource;
    private final String type;
    private final Long version;
    private final List<PatchOperation> operations;

    /**
     * Constructor for the class
     *
     * @param context Name of the context
     * @param offset Offset number of the record
     * @param resource Name of the resource
     * @param type Type of operation to be performed
     * @param version Version Number
     * @param operations JSON Patch payload data
     */
    public PatchChange(
            String context,
            Long offset,
            String resource,
            String type,
            Long version,
            List<PatchOperation> operations) {
        this.context = context;
        this.offset = offset;
        this.resource = resource;
        this.type = type;
        this.version = version;
        this.operations = operations;
    }

    public static PatchChange parse(XContentParser parser)
            throws IOException, IllegalArgumentException, ParsingException, IOException {
        String context = null;
        Long offset = null;
        String resource = null;
        String type = null;
        Long version = null;
        List<PatchOperation> operations = new ArrayList<>();
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
            // Check that we are indeed reading the "context" field
            XContentParserUtils.ensureFieldName(parser, parser.nextToken(), CONTEXT);
            context = parser.text();
            // Check that we are indeed reading the "offset" field
            XContentParserUtils.ensureFieldName(parser, parser.nextToken(), OFFSET);
            offset = parser.longValue();
            // Check that we are indeed reading the "resource" field
            XContentParserUtils.ensureFieldName(parser, parser.nextToken(), RESOURCE);
            resource = parser.text();
            // Check that we are indeed reading the "type" field
            XContentParserUtils.ensureFieldName(parser, parser.nextToken(), TYPE);
            type = parser.text();
            // Check that we are indeed reading the "version" field
            XContentParserUtils.ensureFieldName(parser, parser.nextToken(), VERSION);
            version = parser.longValue();
            // Check that we are indeed reading the "operations" field
            XContentParserUtils.ensureFieldName(parser, parser.nextToken(), OPERATIONS);
            // Check we are at the start of the array
            XContentParserUtils.ensureExpectedToken(
                    XContentParser.Token.START_ARRAY, parser.nextToken(), parser);
            // Iterate over the array and add each JsonPatch object to operations array
            while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                operations.add(PatchOperation.parse(parser));
            }
        }
        return new PatchChange(context, offset, resource, type, version, operations);
    }

    /**
     * Getter for the offset
     *
     * @return the offset as a Long
     */
    public Long getOffset() {
        return this.offset;
    }

    /**
     * Getter for the resource name
     *
     * @return the resource name as a String
     */
    public String getResource() {
        return this.resource;
    }

    /**
     * Getter for the type
     *
     * @return the type as a String
     */
    public String getType() {
        return this.type;
    }

    /**
     * Getter for the version
     *
     * @return the version as a Long
     */
    /**
     * Getter for the context name
     *
     * @return the context name as a String
     */
    public String getContext() {
        return this.context;
    }

    /**
     * Getter for the operations
     *
     * @return the operations as a List of JsonPatch
     */
    public List<PatchOperation> getOperations() {
        return this.operations;
    }

    /**
     * Getter for the version
     *
     * @return the version as a Long
     */
    public Long getVersion() {
        return this.version;
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
        builder.field(CONTEXT, this.context);
        builder.field(OFFSET, this.offset);
        builder.field(RESOURCE, this.resource);
        builder.field(TYPE, this.type);
        builder.field(VERSION, this.version);
        builder.startArray(OPERATIONS);
        for (PatchOperation operation : operations) {
            operation.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
        }
        builder.endArray();
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "PatchChange{"
                + "context='"
                + context
                + '\''
                + ", offset="
                + offset
                + ", resource='"
                + resource
                + '\''
                + ", type='"
                + type
                + '\''
                + ", version="
                + version
                + ", operations="
                + operations
                + '}';
    }
}
