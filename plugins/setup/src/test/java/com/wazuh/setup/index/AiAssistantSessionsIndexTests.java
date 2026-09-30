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
package com.wazuh.setup.index;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for the opaque {@code version} token {@link AiAssistantSessionsIndex} round-trips.
 * OpenSearch has no single row version, so the token carries the {@code seq_no}/{@code
 * primary_term} pair a backing-index write must supply — see {@link
 * AiAssistantSessionsIndex#replace}.
 */
public class AiAssistantSessionsIndexTests extends OpenSearchTestCase {

    public void testVersionTokenRoundTrips() {
        String token = AiAssistantSessionsIndex.encodeVersion(7, 1);
        assertEquals("7:1", token);

        long[] decoded = AiAssistantSessionsIndex.decodeVersion(token);
        assertNotNull(decoded);
        assertEquals(7L, decoded[0]);
        assertEquals(1L, decoded[1]);
    }

    public void testVersionTokenRoundTripsForRandomPairs() {
        long seqNo = randomLongBetween(0, Long.MAX_VALUE);
        long primaryTerm = randomLongBetween(0, Long.MAX_VALUE);
        long[] decoded =
                AiAssistantSessionsIndex.decodeVersion(
                        AiAssistantSessionsIndex.encodeVersion(seqNo, primaryTerm));
        assertNotNull(decoded);
        assertEquals(seqNo, decoded[0]);
        assertEquals(primaryTerm, decoded[1]);
    }

    public void testUndecodableTokenIsTreatedAsAbsent() {
        // The token's contract is "opaque, never validated beyond round-tripping", so anything that
        // is not exactly the pair shape is treated as no token at all rather than rejected — the
        // write then falls back to the pair the request itself just read.
        assertNull(AiAssistantSessionsIndex.decodeVersion(null));
        assertNull(AiAssistantSessionsIndex.decodeVersion(""));
        assertNull(AiAssistantSessionsIndex.decodeVersion("7"));
        assertNull(AiAssistantSessionsIndex.decodeVersion("7:"));
        assertNull(AiAssistantSessionsIndex.decodeVersion(":1"));
        assertNull(AiAssistantSessionsIndex.decodeVersion("7:1:2"));
        assertNull(AiAssistantSessionsIndex.decodeVersion("-1:1"));
        assertNull(AiAssistantSessionsIndex.decodeVersion("a:b"));
        assertNull(AiAssistantSessionsIndex.decodeVersion(" 7:1 "));
        // A stale token from a build that emitted saved-objects opaque version strings.
        assertNull(AiAssistantSessionsIndex.decodeVersion("WzEyLDFd"));
        // Numerically shaped but out of long range.
        assertNull(AiAssistantSessionsIndex.decodeVersion("99999999999999999999:1"));
    }
}
