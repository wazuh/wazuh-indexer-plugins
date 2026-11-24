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

/** Tests for the classification of an index by its schema versions. */
public class SchemaStatusTests extends OpenSearchTestCase {

    /** An index at the shipped version is up to date. */
    public void testSameVersionIsUpToDate() {
        assertEquals(SchemaStatus.UP_TO_DATE, SchemaStatus.classify(50300, 50300, 50200));
    }

    /**
     * An index at or above the compatibility version, but below the shipped one, upgrades in place.
     */
    public void testCompatibleVersionUpgradesInPlace() {
        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, SchemaStatus.classify(50200, 50300, 50200));
        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, SchemaStatus.classify(50201, 50300, 50200));
    }

    /** An index below the compatibility version must be rebuilt. */
    public void testOlderVersionRequiresRebuild() {
        assertEquals(SchemaStatus.REBUILD_REQUIRED, SchemaStatus.classify(50100, 50300, 50200));
    }

    /** An index without a version (0) must be rebuilt, unless the template has no history. */
    public void testMissingVersionRequiresRebuild() {
        assertEquals(SchemaStatus.REBUILD_REQUIRED, SchemaStatus.classify(0, 50000, 50000));
    }

    /** A template whose compat equals its schema version accepts no in-place upgrade. */
    public void testBreakingTemplateRequiresRebuildOfEveryOlderIndex() {
        assertEquals(SchemaStatus.REBUILD_REQUIRED, SchemaStatus.classify(50299, 50300, 50300));
        assertEquals(SchemaStatus.UP_TO_DATE, SchemaStatus.classify(50300, 50300, 50300));
    }

    /** An index newer than the shipped template (a downgrade) is left alone. */
    public void testNewerVersionIsUpToDate() {
        assertEquals(SchemaStatus.UP_TO_DATE, SchemaStatus.classify(50400, 50300, 50200));
    }

    /** The stored values round-trip. */
    public void testValues() {
        for (SchemaStatus status : SchemaStatus.values()) {
            assertEquals(status, SchemaStatus.fromValue(status.getValue()));
        }
        assertEquals("rebuild_required", SchemaStatus.REBUILD_REQUIRED.getValue());
        expectThrows(IllegalArgumentException.class, () -> SchemaStatus.fromValue("unknown"));
    }
}
