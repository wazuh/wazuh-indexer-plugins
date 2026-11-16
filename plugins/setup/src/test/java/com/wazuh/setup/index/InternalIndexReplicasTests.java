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

import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

/** Tests for {@link InternalIndexReplicas}. */
public class InternalIndexReplicasTests extends OpenSearchTestCase {

    private final InternalIndexReplicas provider = new InternalIndexReplicas();

    /** ISM history indices, from their first creation and from a rollover, get the Wazuh range. */
    public void testIsmHistoryIndices() {
        assertAutoExpand(".opendistro-ism-managed-index-history-first-1", false);
        assertAutoExpand(".opendistro-ism-managed-index-history-second-000002", false);
    }

    /** Backing indices of the audit log data stream get the Wazuh range. */
    public void testAuditLogBackingIndices() {
        assertAutoExpand(".ds-security-auditlogs-000001", true);
        assertAutoExpand(".ds-security-auditlogs-000002", true);
    }

    /** Any other index, including the ISM config index and Wazuh streams, gets nothing. */
    public void testOtherIndices() {
        for (String index :
                new String[] {
                    ".opendistro-ism-config",
                    ".opendistro-job-scheduler-lock",
                    "security-auditlogs",
                    ".ds-wazuh-events-v5-security-000001",
                    "wazuh-states-vulnerabilities"
                }) {
            assertEquals(
                    index,
                    Settings.EMPTY,
                    this.provider.getAdditionalIndexSettings(index, false, Settings.EMPTY));
        }
    }

    private void assertAutoExpand(String index, boolean isDataStreamIndex) {
        Settings settings =
                this.provider.getAdditionalIndexSettings(index, isDataStreamIndex, Settings.EMPTY);
        assertEquals(
                index,
                InternalIndexReplicas.AUTO_EXPAND_REPLICAS,
                settings.get(IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS));
        assertEquals(index, 1, settings.size());
    }
}
