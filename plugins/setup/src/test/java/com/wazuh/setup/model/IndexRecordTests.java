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
package com.wazuh.setup.model;

import org.opensearch.test.OpenSearchTestCase;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/** Tests for the stored form of an {@link IndexRecord}. */
public class IndexRecordTests extends OpenSearchTestCase {

    /** The record is classified when built from its versions. */
    public void testOfClassifies() {
        IndexRecord record = IndexRecord.of("wazuh-states-sca", 50200, 50300, 50200, null);

        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, record.status());
        assertTrue(record.isPending());
        assertNull(record.step());
        assertFalse(IndexRecord.of("wazuh-states-sca", 50300, 50300, 50200, null).isPending());
    }

    /** A record survives a round trip through its stored form, step included. */
    public void testRoundTrip() {
        Instant now = Instant.parse("2026-11-17T10:00:00Z");
        IndexRecord record =
                new IndexRecord(
                        "wazuh-states-sca",
                        50000,
                        50300,
                        50200,
                        SchemaStatus.REBUILD_REQUIRED,
                        "mappings_updated",
                        now);

        Map<String, Object> source = record.toMap();
        assertEquals("wazuh-states-sca", source.get(IndexRecord.KEY_INDEX));
        assertEquals(50000L, source.get(IndexRecord.KEY_INSTALLED));
        assertEquals(50300L, source.get(IndexRecord.KEY_SHIPPED));
        assertEquals(50200L, source.get(IndexRecord.KEY_COMPAT));
        assertEquals("rebuild_required", source.get(IndexRecord.KEY_STATUS));
        assertEquals("mappings_updated", source.get(IndexRecord.KEY_STEP));
        assertEquals("2026-11-17T10:00:00Z", source.get(IndexRecord.KEY_UPDATED_AT));

        // OpenSearch hands integers back as Integer when they fit.
        Map<String, Object> stored = new HashMap<>(source);
        stored.put(IndexRecord.KEY_INSTALLED, 50000);
        IndexRecord parsed = IndexRecord.fromMap(stored);
        assertEquals(record.index(), parsed.index());
        assertEquals(record.installed(), parsed.installed());
        assertEquals(record.shipped(), parsed.shipped());
        assertEquals(record.compat(), parsed.compat());
        assertEquals(record.status(), parsed.status());
        assertEquals(record.step(), parsed.step());
        assertEquals(now, parsed.updatedAt());
    }

    /** A record without a step stores none and reads back none. */
    public void testStepIsOptional() {
        IndexRecord record = IndexRecord.of("wazuh-states-sca", 50300, 50300, 50200, null);

        Map<String, Object> source = record.toMap();
        assertFalse(source.containsKey(IndexRecord.KEY_STEP));
        assertNull(IndexRecord.fromMap(source).step());
    }

    /** A malformed stored record is rejected rather than misread. */
    public void testMalformedRecordIsRejected() {
        Map<String, Object> source = IndexRecord.of("x", 50300, 50300, 50200, null).toMap();
        source.remove(IndexRecord.KEY_STATUS);
        expectThrows(IllegalArgumentException.class, () -> IndexRecord.fromMap(source));

        Map<String, Object> notANumber = IndexRecord.of("x", 50300, 50300, 50200, null).toMap();
        notANumber.put(IndexRecord.KEY_SHIPPED, "50300");
        expectThrows(IllegalArgumentException.class, () -> IndexRecord.fromMap(notANumber));
    }
}
