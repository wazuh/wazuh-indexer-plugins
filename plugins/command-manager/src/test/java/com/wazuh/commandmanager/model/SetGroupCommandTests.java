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
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.*;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.mockito.InjectMocks;

import static com.wazuh.commandmanager.model.SetGroupCommand.parse;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class SetGroupCommandTests extends OpenSearchIntegTestCase {
    private static final Logger log = LogManager.getLogger(SetGroupCommandTests.class);

    @InjectMocks private SetGroupCommand setGroupCommand;

    // @Mock private MediaType mediaType = mock(MediaType.class);

    public void testParseValidGroups() throws IOException {
        // Create an XContentParser with a valid JSON
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field("groups", Arrays.asList("group1", "group2"));
        builder.endObject();
        BytesReference bytes = BytesReference.bytes(builder);
        MediaType mediaType = MediaTypeRegistry.JSON;
        log.info("THIS mediaType: {}", mediaType.mediaType());
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
        Args args = parse(parser);

        // Verify the result
        assertNotNull(args);
        assertEquals(1, args.getArgs().size());
        assertTrue(args.getArgs().containsKey("groups"));
        Object groupsObj = args.getArgs().get("groups");
        if (groupsObj instanceof List) {
            List<String> groups = (List<String>) groupsObj;
            assertEquals(2, groups.size());
            log.info("groups: {}", groups.toString());
            assertEquals("group1", groups.get(0));
            assertEquals("group2", groups.get(1));
        } else {
            fail("Expected groups to be a List, but it was: " + groupsObj.getClass().getName());
        }
    }
}
