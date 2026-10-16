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

/** Unit tests for {@link TriggerUpdateRequest}. */
public class TriggerUpdateRequestTests extends OpenSearchTestCase {

    /** A request built without arguments is a regular, online update. */
    public void testDefaultIsOnline() {
        assertFalse(new TriggerUpdateRequest().isOffline());
        assertNull(new TriggerUpdateRequest().validate());
    }

    /** The offline flag survives the transport serialization. */
    public void testSerializationRoundTrip() throws IOException {
        for (boolean offline : new boolean[] {true, false}) {
            try (BytesStreamOutput out = new BytesStreamOutput()) {
                new TriggerUpdateRequest(offline).writeTo(out);
                try (StreamInput in = out.bytes().streamInput()) {
                    assertEquals(offline, new TriggerUpdateRequest(in).isOffline());
                }
            }
        }
    }
}
