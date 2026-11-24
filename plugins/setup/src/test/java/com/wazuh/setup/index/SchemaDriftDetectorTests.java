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

import org.opensearch.Version;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.SchemaStatus;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link SchemaDriftDetector}: the installed version is read from the live index of every
 * index family, classified against the shipped template, and recorded.
 *
 * <p>The shipped template under test is {@code templates/versioned.json} from the test resources:
 * schema version 50300, compatible from 50200.
 */
public class SchemaDriftDetectorTests extends OpenSearchTestCase {

    private static final String TEMPLATE = "templates/versioned";

    private ClusterService clusterService;
    private SetupStatusIndex statusIndex;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.clusterService = mock(ClusterService.class);
        this.statusIndex = mock(SetupStatusIndex.class);
        when(this.statusIndex.getIndexRecord(anyString())).thenReturn(Optional.empty());
    }

    /** Builds the metadata of a concrete index carrying the given schema version (none when 0). */
    private static IndexMetadata index(String name, long schemaVersion) throws IOException {
        return indexBuilder(name, schemaVersion).build();
    }

    /** Starts the metadata of a concrete index carrying the given schema version (none when 0). */
    private static IndexMetadata.Builder indexBuilder(String name, long schemaVersion)
            throws IOException {
        String meta =
                schemaVersion == 0
                        ? ""
                        : ", \"_meta\": {\"schema_version\": "
                                + schemaVersion
                                + ", \"compat_version\": "
                                + schemaVersion
                                + "}";
        return IndexMetadata.builder(name)
                .settings(Settings.builder().put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .putMapping("{\"properties\": {\"name\": {\"type\": \"keyword\"}}" + meta + "}");
    }

    private void cluster(Metadata.Builder metadata) {
        ClusterState state = ClusterState.builder(ClusterName.DEFAULT).metadata(metadata).build();
        when(this.clusterService.state()).thenReturn(state);
    }

    private Index managed(String name) {
        Index index = new StateIndex(name, TEMPLATE);
        index.setClusterService(this.clusterService);
        return index;
    }

    private IndexRecord detectOne(Index index) {
        List<IndexRecord> records = new SchemaDriftDetector(List.of(index), this.statusIndex).detect();
        assertEquals(1, records.size());
        ArgumentCaptor<IndexRecord> written = ArgumentCaptor.forClass(IndexRecord.class);
        verify(this.statusIndex).putIndexRecord(written.capture());
        assertEquals(records.get(0).toMap(), written.getValue().toMap());
        return records.get(0);
    }

    /** A concrete index at the shipped version is recorded as up to date. */
    public void testUpToDateIndex() throws Exception {
        this.cluster(Metadata.builder().put(index("wazuh-states-sca", 50300), false));

        IndexRecord record = this.detectOne(this.managed("wazuh-states-sca"));

        assertEquals("wazuh-states-sca", record.index());
        assertEquals(50300, record.installed());
        assertEquals(50300, record.shipped());
        assertEquals(50200, record.compat());
        assertEquals(SchemaStatus.UP_TO_DATE, record.status());
        assertNull(record.step());
    }

    /** A concrete index at the compatibility version is recorded as upgradable in place. */
    public void testCompatibleIndex() throws Exception {
        this.cluster(Metadata.builder().put(index("wazuh-states-sca", 50200), false));

        IndexRecord record = this.detectOne(this.managed("wazuh-states-sca"));

        assertEquals(50200, record.installed());
        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, record.status());
    }

    /** A concrete index older than the compatibility version is recorded as needing a rebuild. */
    public void testOldIndex() throws Exception {
        this.cluster(Metadata.builder().put(index("wazuh-states-sca", 50100), false));

        IndexRecord record = this.detectOne(this.managed("wazuh-states-sca"));

        assertEquals(SchemaStatus.REBUILD_REQUIRED, record.status());
    }

    /** An index with no {@code _meta} is version 0 and needs a rebuild. */
    public void testIndexWithoutMeta() throws Exception {
        this.cluster(Metadata.builder().put(index("wazuh-states-sca", 0), false));

        IndexRecord record = this.detectOne(this.managed("wazuh-states-sca"));

        assertEquals(0, record.installed());
        assertEquals(SchemaStatus.REBUILD_REQUIRED, record.status());
    }

    /** An index that resolves to nothing is version 0 too, and reported rather than skipped. */
    public void testMissingIndex() throws Exception {
        this.cluster(Metadata.builder());

        IndexRecord record = this.detectOne(this.managed("wazuh-states-sca"));

        assertEquals(0, record.installed());
        assertEquals(SchemaStatus.REBUILD_REQUIRED, record.status());
    }

    /** A data stream is read through its write index, the latest backing index. */
    public void testDataStreamResolvesToTheWriteIndex() throws Exception {
        String first = DataStream.getDefaultBackingIndexName("wazuh-events-v5-security", 1);
        String second = DataStream.getDefaultBackingIndexName("wazuh-events-v5-security", 2);
        IndexMetadata firstMetadata = index(first, 50100);
        IndexMetadata secondMetadata = index(second, 50200);
        DataStream stream =
                new DataStream(
                        "wazuh-events-v5-security",
                        new DataStream.TimestampField("@timestamp"),
                        List.of(firstMetadata.getIndex(), secondMetadata.getIndex()));
        this.cluster(
                Metadata.builder().put(firstMetadata, false).put(secondMetadata, false).put(stream));
        Index index = new StreamIndex("wazuh-events-v5-security", TEMPLATE);
        index.setClusterService(this.clusterService);

        IndexRecord record = this.detectOne(index);

        assertEquals(50200, record.installed());
        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, record.status());
    }

    /** A content alias is read through its write index, whichever physical slot it points at. */
    public void testAliasResolvesToTheWriteIndex() throws Exception {
        IndexMetadata old = index("wazuh-threatintel-rules-a", 50100);
        IndexMetadata live =
                indexBuilder("wazuh-threatintel-rules-b", 50300)
                        .putAlias(AliasMetadata.builder("wazuh-threatintel-rules").writeIndex(true))
                        .build();
        this.cluster(Metadata.builder().put(old, false).put(live, false));
        Index index = new ContentIndex("wazuh-threatintel-rules", TEMPLATE);
        index.setClusterService(this.clusterService);

        IndexRecord record = this.detectOne(index);

        assertEquals(50300, record.installed());
        assertEquals(SchemaStatus.UP_TO_DATE, record.status());
    }

    /** A pending index keeps the step its previous record carried, so the upgrade resumes there. */
    public void testPendingIndexKeepsItsRecordedStep() throws Exception {
        this.cluster(Metadata.builder().put(index("wazuh-states-sca", 50200), false));
        when(this.statusIndex.getIndexRecord("wazuh-states-sca"))
                .thenReturn(
                        Optional.of(
                                new IndexRecord(
                                        "wazuh-states-sca",
                                        50200,
                                        50300,
                                        50200,
                                        SchemaStatus.UPGRADE_IN_PLACE,
                                        "mappings_updated",
                                        Instant.now())));

        IndexRecord record = this.detectOne(this.managed("wazuh-states-sca"));

        assertEquals("mappings_updated", record.step());
        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, record.status());
    }

    /** Once an index is up to date, the step of the finished upgrade is dropped. */
    public void testUpToDateIndexDropsTheStep() throws Exception {
        this.cluster(Metadata.builder().put(index("wazuh-states-sca", 50300), false));
        when(this.statusIndex.getIndexRecord("wazuh-states-sca"))
                .thenReturn(
                        Optional.of(
                                new IndexRecord(
                                        "wazuh-states-sca",
                                        50200,
                                        50300,
                                        50200,
                                        SchemaStatus.UPGRADE_IN_PLACE,
                                        "mappings_updated",
                                        Instant.now())));

        IndexRecord record = this.detectOne(this.managed("wazuh-states-sca"));

        assertNull(record.step());
        assertEquals(SchemaStatus.UP_TO_DATE, record.status());
    }

    /** Indices that do not take part in the versioning get no record. */
    public void testUnversionedIndexIsSkipped() throws Exception {
        this.cluster(Metadata.builder());
        Index ism =
                new IndexStateManagement(IndexStateManagement.ISM_INDEX_NAME, "templates/ism-config");
        ism.setClusterService(this.clusterService);

        List<IndexRecord> records = new SchemaDriftDetector(List.of(ism), this.statusIndex).detect();

        assertTrue(records.isEmpty());
        verify(this.statusIndex, never()).putIndexRecord(any());
    }

    /** A failure names the index and stops the detection. */
    public void testFailureNamesTheIndex() throws Exception {
        this.cluster(Metadata.builder().put(index("wazuh-states-sca", 50300), false));
        Index broken = this.managed("wazuh-states-sca");
        when(this.statusIndex.getIndexRecord("wazuh-states-sca"))
                .thenThrow(new RuntimeException("status index unavailable"));

        IllegalStateException e =
                expectThrows(
                        IllegalStateException.class,
                        () -> new SchemaDriftDetector(List.of(broken), this.statusIndex).detect());

        assertTrue(e.getMessage(), e.getMessage().contains("[wazuh-states-sca]"));
        assertTrue(e.getMessage(), e.getMessage().contains("status index unavailable"));
        verify(this.statusIndex, never()).putIndexRecord(any());
    }
}
