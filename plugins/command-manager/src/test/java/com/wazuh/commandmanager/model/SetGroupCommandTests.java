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

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.*;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class SetGroupCommandTests extends OpenSearchIntegTestCase {

    public void testParseValidGroups() throws IOException {
        // Create an XContentParser with a valid JSON
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field("groups", Arrays.asList("group1", "group2"));
        builder.endObject();
        BytesReference bytes = BytesReference.bytes(builder);
        MediaType mediaType = MediaTypeRegistry.JSON;
        XContentParser parser =
                mediaType
                        .xContent()
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                bytes.streamInput());

        // Initialize the parser
        parser.nextToken();
        // Call the parse method
        Args args = SetGroupCommand.parse(parser);

        // Verify the result
        assertNotNull(args);
        assertEquals(1, args.getArgs().size());
        assertTrue(args.getArgs().containsKey("groups"));
        Object groupsObj = args.getArgs().get("groups");
        if (groupsObj instanceof List) {
            List<String> groups = (List<String>) groupsObj;
            assertEquals(2, groups.size());
            assertEquals("group1", groups.get(0));
            assertEquals("group2", groups.get(1));
        } else {
            fail("Expected groups to be a List, but it was: " + groupsObj.getClass().getName());
        }
    }

    public void testParseInvalidGroups() throws IOException {
        // Create an XContentParser with an invalid JSON, that is not an array
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field("groups", "this isn't an array");
        builder.endObject();
        BytesReference bytes = BytesReference.bytes(builder);
        MediaType mediaType = MediaTypeRegistry.JSON;
        XContentParser parser =
                mediaType
                        .xContent()
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                bytes.streamInput());

        // Call the parse method
        try {
            // Initialize the parser
            parser.nextToken();
            // Test parse method
            SetGroupCommand.parse(parser);
            fail("This must fail because the JSON is not an array.");
        } catch (IOException | IllegalArgumentException e) {
            // Verify that the exception is correct.
            assertEquals(
                    "Expected [command.action.args.groups] to be an array, got [VALUE_STRING]",
                    e.getMessage());
        }
    }

    public void testParseMissingGroups() throws IOException {
        // Create an XContentParser with an invalid JSON, that does not contain the "groups" key
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field("testField", "any-string");
        builder.endObject();
        BytesReference bytes = BytesReference.bytes(builder);
        MediaType mediaType = MediaTypeRegistry.JSON;
        XContentParser parser =
                mediaType
                        .xContent()
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                bytes.streamInput());

        // Call the parse method
        try {
            // Initialize the parser
            parser.nextToken();
            // Test parse method
            SetGroupCommand.parse(parser);
            fail("This must fail because the JSON does not contain the 'groups' key.");
        } catch (IllegalArgumentException e) {
            // Verify that the exception is correct.
            assertEquals(
                    "Expected [command.action.args] to contain the [groups] key, got [testField]",
                    e.getMessage());
        }
    }

    public void testParseEmptyGroups() throws IOException {
        // Create an XContentParser with a valid JSON that contains an empty array for "groups"
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field("groups", List.of());
        builder.endObject();
        BytesReference bytes = BytesReference.bytes(builder);
        MediaType mediaType = MediaTypeRegistry.JSON;
        XContentParser parser =
                mediaType
                        .xContent()
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                bytes.streamInput());

        // Initialize the parser
        parser.nextToken();
        // Test the parse method
        Args args = SetGroupCommand.parse(parser);

        // Verify the result.
        assertNotNull(args);
        assertEquals(1, args.getArgs().size());
        assertTrue(args.getArgs().containsKey("groups"));
        List<String> groups = (List<String>) args.getArgs().get("groups");
        assertEquals(0, groups.size());
    }

    public void testParseNullGroups() throws IOException {
        // Create an XContentParser with a valid JSON that contains a null value for "groups"
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field("groups", (String) null);
        builder.endObject();
        BytesReference bytes = BytesReference.bytes(builder);
        MediaType mediaType = MediaTypeRegistry.JSON;
        XContentParser parser =
                mediaType
                        .xContent()
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                bytes.streamInput());

        // Call the parse method
        try {
            // Initialize the parser
            parser.nextToken();
            // Test parse method
            SetGroupCommand.parse(parser);
            fail("This must fail because the JSON contains a null value.");
        } catch (IllegalArgumentException e) {
            // Verify that the exception is correct.
            assertEquals(
                    "Expected [command.action.args.groups] to be an array, got [VALUE_NULL]", e.getMessage());
        }
    }
}
