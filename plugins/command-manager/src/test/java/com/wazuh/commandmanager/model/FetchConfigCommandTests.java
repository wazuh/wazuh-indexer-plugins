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

import java.util.Arrays;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class FetchConfigCommandTests extends OpenSearchIntegTestCase {

	public void testParse() throws Exception {
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
		Args args = FetchConfigCommand.parse(parser);

		assertEquals(0, args.getArgs().size());
	}
}
