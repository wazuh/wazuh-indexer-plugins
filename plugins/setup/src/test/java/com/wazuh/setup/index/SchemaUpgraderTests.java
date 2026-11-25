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

import org.opensearch.OpenSearchException;
import org.opensearch.Version;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.admin.indices.rollover.RolloverResponse;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.wazuh.setup.config.SetupConfig;
import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.model.SchemaStatus;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link SchemaUpgrader}: the in-place upgrade and its order, its resume and failure
 * paths, and the rollover of a data stream that must be rebuilt.
 *
 * <p>The shipped template under test is {@code templates/states/upgradable.json} from the test
 * resources: schema version 50300, compatible from 50200, with static and dynamic settings.
 */
public class SchemaUpgraderTests extends OpenSearchTestCase {

    private static final String TEMPLATE = "templates/states/upgradable";
    private static final String STATE = "wazuh-states-sca";
    private static final String STREAM = "wazuh-events-v5-security";

    private Client client;
    private IndicesAdminClient indicesAdminClient;
    private ClusterService clusterService;
    private SetupStatusIndex statusIndex;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        this.clusterService = mock(ClusterService.class);
        this.statusIndex = mock(SetupStatusIndex.class);

        doReturn(adminClient).when(this.client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(Settings.EMPTY).when(this.clusterService).getSettings();
        when(this.statusIndex.getIndexRecord(anyString())).thenReturn(Optional.empty());

        this.stubAcknowledged();
    }

    /** Builds the metadata of a concrete index carrying the given schema version. */
    private static IndexMetadata index(String name, long schemaVersion) throws IOException {
        return IndexMetadata.builder(name)
                .settings(Settings.builder().put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .putMapping(
                        "{\"properties\": {\"name\": {\"type\": \"keyword\"}}, \"_meta\": {\"schema_version\": "
                                + schemaVersion
                                + "}}")
                .build();
    }

    private void cluster(Metadata.Builder metadata) {
        ClusterState state = ClusterState.builder(ClusterName.DEFAULT).metadata(metadata).build();
        when(this.clusterService.state()).thenReturn(state);
    }

    /** A state index at the given version. */
    private StateIndex state(long schemaVersion) throws IOException {
        this.cluster(Metadata.builder().put(index(STATE, schemaVersion), false));
        StateIndex index = new StateIndex(STATE, TEMPLATE);
        index.setClient(this.client);
        index.setClusterService(this.clusterService);
        return index;
    }

    /**
     * A data stream whose backing indices carry the given versions, the last being the write index.
     */
    private void streamCluster(long... schemaVersions) throws IOException {
        Metadata.Builder metadata = Metadata.builder();
        List<org.opensearch.core.index.Index> backing = new java.util.ArrayList<>();
        for (int i = 0; i < schemaVersions.length; i++) {
            IndexMetadata backingIndex =
                    index(DataStream.getDefaultBackingIndexName(STREAM, i + 1), schemaVersions[i]);
            metadata.put(backingIndex, false);
            backing.add(backingIndex.getIndex());
        }
        metadata.put(new DataStream(STREAM, new DataStream.TimestampField("@timestamp"), backing));
        this.cluster(metadata);
    }

    private StreamIndex stream(long schemaVersion) throws IOException {
        this.streamCluster(schemaVersion);
        StreamIndex index = new StreamIndex(STREAM, TEMPLATE);
        index.setClient(this.client);
        index.setClusterService(this.clusterService);
        return index;
    }

    private static IndexRecord record(String name, long installed, String step) {
        return IndexRecord.of(name, installed, 50300, 50200, step);
    }

    private IndexRecord upgradeOne(Index index, IndexRecord record) {
        List<IndexRecord> result =
                new SchemaUpgrader(List.of(index), this.statusIndex).upgrade(List.of(record));
        assertEquals(1, result.size());
        return result.get(0);
    }

    private List<IndexRecord> written() {
        ArgumentCaptor<IndexRecord> captor = ArgumentCaptor.forClass(IndexRecord.class);
        verify(this.statusIndex, org.mockito.Mockito.atLeast(0)).putIndexRecord(captor.capture());
        return captor.getAllValues();
    }

    private List<String> mappingsSent() {
        ArgumentCaptor<PutMappingRequest> captor = ArgumentCaptor.forClass(PutMappingRequest.class);
        verify(this.indicesAdminClient, org.mockito.Mockito.atLeast(0)).putMapping(captor.capture());
        return captor.getAllValues().stream().map(PutMappingRequest::source).toList();
    }

    /** An index at the shipped version is not touched and its record not rewritten. */
    public void testUpToDateIndexIsNotTouched() throws Exception {
        IndexRecord record = record(STATE, 50300, null);

        IndexRecord result = this.upgradeOne(this.state(50300), record);

        assertSame(record, result);
        verifyNoInteractions(this.indicesAdminClient);
        verify(this.statusIndex, never()).putIndexRecord(any());
    }

    /**
     * An upgrade in place merges the shipped mappings without their _meta, applies the dynamic
     * settings, then stamps the versions, recording each step and ending up to date.
     */
    public void testInPlaceUpgradeAppliesMappingsThenSettingsThenStampsTheVersion() throws Exception {
        IndexRecord result = this.upgradeOne(this.state(50200), record(STATE, 50200, null));

        List<String> mappings = this.mappingsSent();
        assertEquals(2, mappings.size());
        assertTrue(mappings.get(0), mappings.get(0).contains("\"properties\""));
        assertFalse(mappings.get(0), mappings.get(0).contains("_meta"));
        assertTrue(mappings.get(1), mappings.get(1).contains("\"_meta\""));
        assertTrue(mappings.get(1), mappings.get(1).contains("50300"));
        assertFalse(mappings.get(1), mappings.get(1).contains("properties"));

        ArgumentCaptor<UpdateSettingsRequest> settings =
                ArgumentCaptor.forClass(UpdateSettingsRequest.class);
        verify(this.indicesAdminClient).updateSettings(settings.capture());
        assertArrayEquals(new String[] {STATE}, settings.getValue().indices());
        assertEquals("5s", settings.getValue().settings().get("index.refresh_interval"));
        assertEquals(
                List.of("name", "message"),
                settings.getValue().settings().getAsList("index.query.default_field"));
        assertEquals("100", settings.getValue().settings().get("index.mapping.total_fields.limit"));
        assertNull(settings.getValue().settings().get("index.number_of_shards"));
        assertNull(settings.getValue().settings().get("index.codec"));

        InOrder order = inOrder(this.indicesAdminClient);
        order.verify(this.indicesAdminClient).putMapping(any(PutMappingRequest.class));
        order.verify(this.indicesAdminClient).updateSettings(any(UpdateSettingsRequest.class));
        order.verify(this.indicesAdminClient).putMapping(any(PutMappingRequest.class));

        List<IndexRecord> records = this.written();
        assertEquals(3, records.size());
        assertEquals(Index.STEP_MAPPINGS_UPDATED, records.get(0).step());
        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, records.get(0).status());
        assertEquals(Index.STEP_SETTINGS_UPDATED, records.get(1).step());
        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, records.get(1).status());
        assertNull(records.get(2).step());
        assertEquals(50300, records.get(2).installed());
        assertEquals(SchemaStatus.UP_TO_DATE, records.get(2).status());
        assertEquals(records.get(2).toMap(), result.toMap());
    }

    /** A mapping OpenSearch rejects marks the index as needing a rebuild, with nothing else done. */
    public void testMappingConflictMarksTheIndexAsRebuildRequired() throws Exception {
        ActionFuture<AcknowledgedResponse> rejected = mock(ActionFuture.class);
        doThrow(
                        new IllegalArgumentException(
                                "mapper [name] cannot be changed from type [keyword] to [text]"))
                .when(rejected)
                .actionGet(anyLong());
        doReturn(rejected).when(this.indicesAdminClient).putMapping(any(PutMappingRequest.class));

        IndexRecord result = this.upgradeOne(this.state(50200), record(STATE, 50200, null));

        assertEquals(SchemaStatus.REBUILD_REQUIRED, result.status());
        assertEquals(50200, result.installed());
        assertNull(result.step());
        verify(this.indicesAdminClient, times(1)).putMapping(any(PutMappingRequest.class));
        verify(this.indicesAdminClient, never()).updateSettings(any(UpdateSettingsRequest.class));
        List<IndexRecord> records = this.written();
        assertEquals(1, records.size());
        assertEquals(SchemaStatus.REBUILD_REQUIRED, records.get(0).status());
    }

    /** An upgrade interrupted after the mappings resumes at the settings. */
    public void testUpgradeResumesAfterTheMappingsStep() throws Exception {
        IndexRecord result =
                this.upgradeOne(this.state(50200), record(STATE, 50200, Index.STEP_MAPPINGS_UPDATED));

        List<String> mappings = this.mappingsSent();
        assertEquals(1, mappings.size());
        assertTrue(mappings.get(0), mappings.get(0).contains("\"_meta\""));
        verify(this.indicesAdminClient).updateSettings(any(UpdateSettingsRequest.class));
        List<IndexRecord> records = this.written();
        assertEquals(2, records.size());
        assertEquals(Index.STEP_SETTINGS_UPDATED, records.get(0).step());
        assertEquals(SchemaStatus.UP_TO_DATE, result.status());
    }

    /** An upgrade interrupted after the settings only stamps the versions. */
    public void testUpgradeResumesAfterTheSettingsStep() throws Exception {
        IndexRecord result =
                this.upgradeOne(this.state(50200), record(STATE, 50200, Index.STEP_SETTINGS_UPDATED));

        assertEquals(1, this.mappingsSent().size());
        verify(this.indicesAdminClient, never()).updateSettings(any(UpdateSettingsRequest.class));
        assertEquals(1, this.written().size());
        assertEquals(SchemaStatus.UP_TO_DATE, result.status());
        assertEquals(50300, result.installed());
    }

    /** A settings update that fails leaves the index pending after the mappings step. */
    public void testSettingsFailureLeavesTheIndexPending() throws Exception {
        ActionFuture<AcknowledgedResponse> failed = mock(ActionFuture.class);
        doThrow(new OpenSearchException("boom")).when(failed).actionGet(anyLong());
        doReturn(failed).when(this.indicesAdminClient).updateSettings(any(UpdateSettingsRequest.class));
        IndexRecord afterMappings = record(STATE, 50200, Index.STEP_MAPPINGS_UPDATED);
        when(this.statusIndex.getIndexRecord(STATE)).thenReturn(Optional.of(afterMappings));

        IndexRecord result = this.upgradeOne(this.state(50200), record(STATE, 50200, null));

        assertEquals(SchemaStatus.UPGRADE_IN_PLACE, result.status());
        assertEquals(Index.STEP_MAPPINGS_UPDATED, result.step());
        // The mappings went in; the versions were not stamped.
        assertEquals(1, this.mappingsSent().size());
        assertFalse(this.mappingsSent().get(0).contains("_meta"));
    }

    /** A data stream that must be rebuilt is rolled over, and its new write index is up to date. */
    public void testStreamThatMustBeRebuiltIsRolledOver() throws Exception {
        StreamIndex stream = this.stream(50100);
        RolloverResponse rolled =
                new RolloverResponse(
                        DataStream.getDefaultBackingIndexName(STREAM, 1),
                        DataStream.getDefaultBackingIndexName(STREAM, 2),
                        java.util.Map.of(),
                        false,
                        true,
                        true,
                        true);
        ActionFuture<RolloverResponse> future = mock(ActionFuture.class);
        when(future.actionGet(anyLong()))
                .thenAnswer(
                        invocation -> {
                            // The new write index is created from the stored template.
                            this.streamCluster(50100, 50300);
                            return rolled;
                        });
        doReturn(future).when(this.indicesAdminClient).rolloverIndex(any(RolloverRequest.class));

        IndexRecord result = this.upgradeOne(stream, record(STREAM, 50100, null));

        ArgumentCaptor<RolloverRequest> request = ArgumentCaptor.forClass(RolloverRequest.class);
        verify(this.indicesAdminClient).rolloverIndex(request.capture());
        assertEquals(STREAM, request.getValue().getRolloverTarget());
        verify(this.indicesAdminClient, never()).putMapping(any(PutMappingRequest.class));
        verify(this.indicesAdminClient, never()).updateSettings(any(UpdateSettingsRequest.class));
        assertEquals(SchemaStatus.UP_TO_DATE, result.status());
        assertEquals(50300, result.installed());
        assertNull(result.step());
    }

    /** A state index that must be rebuilt is left pending: the rebuild is not automated here. */
    public void testStateIndexThatMustBeRebuiltStaysPending() throws Exception {
        IndexRecord record = record(STATE, 50100, null);

        IndexRecord result = this.upgradeOne(this.state(50100), record);

        assertSame(record, result);
        verifyNoInteractions(this.indicesAdminClient);
        verify(this.statusIndex, never()).putIndexRecord(any());
    }

    /** A record of an index the plugin does not manage is left as it is. */
    public void testUnknownIndexIsLeftAlone() throws Exception {
        IndexRecord record = record("wazuh-unknown", 50200, null);

        IndexRecord result = this.upgradeOne(this.state(50200), record);

        assertSame(record, result);
        verifyNoInteractions(this.indicesAdminClient);
    }

    /** Only the dynamic settings of the template survive, with the index prefix normalized. */
    public void testDynamicSettingsDropTheStaticOnes() throws Exception {
        StateIndex index = this.state(50200);
        IndexTemplate template = index.loadTemplate();

        Settings dynamic =
                Index.dynamicSettings(
                        Settings.builder().loadFromMap(template.getSettings()).build(), STATE);

        assertEquals(
                Set.of(
                        "index.refresh_interval",
                        "index.query.default_field",
                        "index.mapping.total_fields.limit"),
                dynamic.keySet());
    }

    /** The settings applied are the stored ones: the overrides of the configuration file count. */
    public void testInPlaceUpgradeAppliesTheOverridesOfTheConfiguration() throws Exception {
        Path directory = createTempDir();
        Files.writeString(
                directory.resolve(SetupConfig.FILE),
                "templates.states.upgradable.settings.index.refresh_interval: 9s\n"
                        + "templates.states.upgradable.settings.index.number_of_shards: 3\n",
                StandardCharsets.UTF_8);
        SetupConfig config =
                SetupConfig.load(directory, List.of(TEMPLATE), List.of(), NamedXContentRegistry.EMPTY);
        StateIndex index = this.state(50200);
        index.setConfig(config);

        this.upgradeOne(index, record(STATE, 50200, null));

        ArgumentCaptor<UpdateSettingsRequest> settings =
                ArgumentCaptor.forClass(UpdateSettingsRequest.class);
        verify(this.indicesAdminClient).updateSettings(settings.capture());
        assertEquals("9s", settings.getValue().settings().get("index.refresh_interval"));
        assertNull(settings.getValue().settings().get("index.number_of_shards"));
    }

    /**
     * A rollover whose record cannot be written fails the initialization naming the stream, and is
     * not repeated: the next detection reads the new write index, which is at the shipped version.
     */
    public void testRolloverIsNotRepeatedWhenItsRecordCannotBeWritten() throws Exception {
        StreamIndex stream = this.stream(50100);
        this.stubRollover();
        doThrow(new OpenSearchException("status index down"))
                .when(this.statusIndex)
                .putIndexRecord(any());

        IllegalStateException e =
                expectThrows(
                        IllegalStateException.class,
                        () ->
                                new SchemaUpgrader(List.of(stream), this.statusIndex)
                                        .upgrade(List.of(record(STREAM, 50100, null))));

        assertTrue(e.getMessage(), e.getMessage().contains("[" + STREAM + "]"));
        assertTrue(e.getMessage(), e.getMessage().contains("status index down"));

        // Next boot: the detection classifies the stream from its new write index.
        SetupStatusIndex nextBoot = mock(SetupStatusIndex.class);
        when(nextBoot.getIndexRecord(anyString())).thenReturn(Optional.empty());
        List<IndexRecord> records = new SchemaDriftDetector(List.of(stream), nextBoot).detect();
        assertEquals(SchemaStatus.UP_TO_DATE, records.get(0).status());
        new SchemaUpgrader(List.of(stream), nextBoot).upgrade(records);
        verify(this.indicesAdminClient, times(1)).rolloverIndex(any(RolloverRequest.class));
    }

    /** Stubs a rollover that creates a second backing index at the shipped version. */
    @SuppressWarnings("unchecked")
    private void stubRollover() {
        RolloverResponse rolled =
                new RolloverResponse(
                        DataStream.getDefaultBackingIndexName(STREAM, 1),
                        DataStream.getDefaultBackingIndexName(STREAM, 2),
                        java.util.Map.of(),
                        false,
                        true,
                        true,
                        true);
        ActionFuture<RolloverResponse> future = mock(ActionFuture.class);
        when(future.actionGet(anyLong()))
                .thenAnswer(
                        invocation -> {
                            this.streamCluster(50100, 50300);
                            return rolled;
                        });
        doReturn(future).when(this.indicesAdminClient).rolloverIndex(any(RolloverRequest.class));
    }

    /** Stubs acknowledged mapping and settings updates. */
    @SuppressWarnings("unchecked")
    private void stubAcknowledged() {
        AcknowledgedResponse acknowledged = new AcknowledgedResponse(true);
        ActionFuture<AcknowledgedResponse> future = mock(ActionFuture.class);
        doReturn(acknowledged).when(future).actionGet(anyLong());
        doReturn(future).when(this.indicesAdminClient).putMapping(any(PutMappingRequest.class));
        doReturn(future).when(this.indicesAdminClient).updateSettings(any(UpdateSettingsRequest.class));
    }
}
