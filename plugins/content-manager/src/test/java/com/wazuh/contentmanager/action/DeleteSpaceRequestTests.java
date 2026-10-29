/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.action;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import com.wazuh.contentmanager.rest.model.SpaceClearScope;

/** Unit tests for {@link DeleteSpaceRequest}. */
public class DeleteSpaceRequestTests extends OpenSearchTestCase {

    /** The clear scope survives the transport serialization, for every scope. */
    public void testSerializationRoundTripsScope() throws IOException {
        for (SpaceClearScope scope : SpaceClearScope.values()) {
            try (BytesStreamOutput out = new BytesStreamOutput()) {
                new DeleteSpaceRequest("draft", scope).writeTo(out);
                try (StreamInput in = out.bytes().streamInput()) {
                    DeleteSpaceRequest read = new DeleteSpaceRequest(in);
                    assertEquals(scope, read.getScope());
                    assertEquals("draft", read.getSpaceName());
                }
            }
        }
    }

    /** The legacy single-argument constructor keeps the full reset behaviour. */
    public void testLegacyConstructorDefaultsToFull() {
        assertEquals(SpaceClearScope.FULL, new DeleteSpaceRequest("draft").getScope());
    }
}
