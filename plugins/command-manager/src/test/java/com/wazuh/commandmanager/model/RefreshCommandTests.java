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
import java.util.List;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class RefreshCommandTests extends OpenSearchIntegTestCase {

    public void testParseValidSingleIndex() throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field("index", "test_index");
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

        parser.nextToken();
        Args args = RefreshCommand.parse(parser);

        assertNotNull(args);
        assertTrue(args.getArgs().get("index") instanceof List);
        assertEquals("test_index", ((List<?>) args.getArgs().get("index")).get(0));
    }

    public void testParseValidMultipleIndices() throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field("index", new String[]{"index1", "index2"});
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

        parser.nextToken();
        Args args = RefreshCommand.parse(parser);

        assertNotNull(args);
        assertTrue(args.getArgs().get("index") instanceof List);
        List<?> indices = (List<?>) args.getArgs().get("index");
        assertEquals(2, indices.size());
        assertEquals("index1", indices.get(0));
        assertEquals("index2", indices.get(1));
    }

    public void testParseMissingIndexKey() {
        try {
            XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.startObject();
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
            parser.nextToken();
            RefreshCommand.parse(parser);
        } catch (Exception e) {
            fail("Expected no exception to be thrown, but got: " + e.getMessage());
        }
    }

    public void testParseInvalidIndexValue() {
        assertThrows(
            IllegalArgumentException.class,
            () -> {
                XContentBuilder builder = XContentFactory.jsonBuilder();
                builder.startObject();
                builder.field("index", 12345);
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
                parser.nextToken();
                RefreshCommand.parse(parser);
            });
    }

    public void testParseInvalidIndexArray() {
        assertThrows(
            IllegalArgumentException.class,
            () -> {
                XContentBuilder builder = XContentFactory.jsonBuilder();
                builder.startObject();
                builder.field("index", new int[]{1, 2, 3});
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
                parser.nextToken();
                RefreshCommand.parse(parser);
            });
    }
}
