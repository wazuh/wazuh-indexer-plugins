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

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.index.reindex.ReindexRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.SchemaStatus;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link StateIndex}: the alias topology on a fresh cluster, and the one-time
 * migration of a concrete index created before state indices were alias-backed.
 */
public class StateIndexTests extends OpenSearchTestCase {

    private static final String ALIAS = "wazuh-states-sca";
    private static final String PHYSICAL = ALIAS + AliasedIndex.SUFFIX_A;

    private StateIndex stateIndex;
    private Client client;
    private IndicesAdminClient indicesAdminClient;
    private RoutingTable routingTable;
    private Metadata metadata;
    private SetupStatusIndex statusIndex;

    /** Document count returned for each index by the count stub. */
    private final Map<String, Long> counts = new HashMap<>();

    @Override
    public void setUp() throws Exception {
        super.setUp();

        this.client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterService clusterService = mock(ClusterService.class);
        ClusterState clusterState = mock(ClusterState.class);
        this.routingTable = mock(RoutingTable.class);
        this.metadata = mock(Metadata.class);
        this.statusIndex = mock(SetupStatusIndex.class);

        doReturn(Settings.builder().build()).when(clusterService).getSettings();

        this.stateIndex = new StateIndex(ALIAS, "templates/states/sca");
        this.stateIndex.setClient(this.client);
        this.stateIndex.setClusterService(clusterService);
        this.stateIndex.setStatusIndex(this.statusIndex);

        doReturn(adminClient).when(this.client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(clusterState).when(clusterService).state();
        doReturn(this.routingTable).when(clusterState).getRoutingTable();
        doReturn(this.metadata).when(clusterState).metadata();
        doReturn(new TreeMap<>()).when(this.metadata).getIndicesLookup();

        // Clean cluster by default: neither the concrete index nor the alias exists.
        doReturn(false).when(this.routingTable).hasIndex(anyString());
        doReturn(false).when(this.metadata).hasIndex(anyString());
        doReturn(false).when(this.metadata).hasAlias(anyString());
        when(this.statusIndex.getIndexRecord(anyString())).thenReturn(Optional.empty());

        this.stubCreate();
        this.stubMigrationCalls();
    }

    /** On a clean cluster the "-a" index is created with the public alias as its write index. */
    public void testCreateIndexCreatesPhysicalIndexWithWriteAlias() {
        this.stateIndex.createIndex(ALIAS);

        ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.indicesAdminClient).create(captor.capture());
        assertEquals(PHYSICAL, captor.getValue().index());
        Set<Alias> aliases = captor.getValue().aliases();
        assertEquals(1, aliases.size());
        Alias alias = aliases.iterator().next();
        assertEquals(ALIAS, alias.name());
        assertEquals(Boolean.TRUE, alias.writeIndex());
        verify(this.client, never()).execute(eq(ReindexAction.INSTANCE), any());
        verify(this.indicesAdminClient, never()).delete(any(DeleteIndexRequest.class));
    }

    /** With the alias on the alternate slot and no "-a" index, nothing is done. */
    public void testCreateIndexIsANoOpWhenTheAliasPointsAtTheAlternateSlot() {
        doReturn(true).when(this.metadata).hasAlias(ALIAS);

        this.stateIndex.createIndex(ALIAS);

        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
        verify(this.indicesAdminClient, never()).aliases(any(IndicesAliasesRequest.class));
        verify(this.client, never()).execute(eq(ReindexAction.INSTANCE), any());
    }

    /** The template patterns cover both physical slots and the alias name. */
    public void testTemplateCoversEverySlot() throws Exception {
        com.wazuh.setup.model.IndexTemplate template = this.stateIndex.loadTemplate();

        this.stateIndex.customizeTemplate(template);

        assertEquals(List.of(ALIAS + "*"), template.getIndexPatterns());
        assertEquals("states-sca", this.stateIndex.templateName("templates/states/sca"));
    }

    /**
     * A concrete index named after the alias, from a cluster created before this change, is migrated:
     * "-a" is created, writes are blocked, every document is copied and counted, and the index is
     * replaced by the alias in one request. Both steps are recorded.
     */
    public void testCreateIndexMigratesAConcreteIndex() {
        doReturn(true).when(this.metadata).hasIndex(ALIAS);
        this.counts.put(ALIAS, 42L);
        this.counts.put(PHYSICAL, 42L);

        this.stateIndex.createIndex(ALIAS);

        // The target is created without the alias: the concrete index still owns that name.
        ArgumentCaptor<CreateIndexRequest> create = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.indicesAdminClient).create(create.capture());
        assertEquals(PHYSICAL, create.getValue().index());
        assertTrue(create.getValue().aliases().isEmpty());

        // Writes to the source are blocked before the copy.
        ArgumentCaptor<UpdateSettingsRequest> block =
                ArgumentCaptor.forClass(UpdateSettingsRequest.class);
        verify(this.indicesAdminClient).updateSettings(block.capture());
        assertArrayEquals(new String[] {ALIAS}, block.getValue().indices());
        assertEquals("true", block.getValue().settings().get(IndexMetadata.SETTING_BLOCKS_WRITE));

        // The copy goes from the concrete index to the target.
        ArgumentCaptor<ReindexRequest> copy = ArgumentCaptor.forClass(ReindexRequest.class);
        verify(this.client).execute(eq(ReindexAction.INSTANCE), copy.capture());
        assertArrayEquals(new String[] {ALIAS}, copy.getValue().getSearchRequest().indices());
        assertEquals(PHYSICAL, copy.getValue().getDestination().index());

        // The concrete index is removed and the alias created in the same request.
        ArgumentCaptor<IndicesAliasesRequest> swap =
                ArgumentCaptor.forClass(IndicesAliasesRequest.class);
        verify(this.indicesAdminClient).aliases(swap.capture());
        List<IndicesAliasesRequest.AliasActions> actions = swap.getValue().getAliasActions();
        assertEquals(2, actions.size());
        assertEquals(IndicesAliasesRequest.AliasActions.Type.REMOVE_INDEX, actions.get(0).actionType());
        assertArrayEquals(new String[] {ALIAS}, actions.get(0).indices());
        assertEquals(IndicesAliasesRequest.AliasActions.Type.ADD, actions.get(1).actionType());
        assertArrayEquals(new String[] {PHYSICAL}, actions.get(1).indices());
        assertArrayEquals(new String[] {ALIAS}, actions.get(1).aliases());
        assertEquals(Boolean.TRUE, actions.get(1).writeIndex());
        verify(this.indicesAdminClient, never()).delete(any(DeleteIndexRequest.class));

        // Block, copy, swap, in that order.
        InOrder order = inOrder(this.indicesAdminClient, this.client);
        order.verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
        order.verify(this.indicesAdminClient).updateSettings(any(UpdateSettingsRequest.class));
        order.verify(this.client).execute(eq(ReindexAction.INSTANCE), any(ReindexRequest.class));
        order.verify(this.indicesAdminClient).aliases(any(IndicesAliasesRequest.class));

        // Both steps are recorded, in order.
        ArgumentCaptor<IndexRecord> records = ArgumentCaptor.forClass(IndexRecord.class);
        verify(this.statusIndex, times(2)).putIndexRecord(records.capture());
        assertEquals(StateIndex.STEP_TARGET_CREATED, records.getAllValues().get(0).step());
        assertEquals(StateIndex.STEP_COPIED, records.getAllValues().get(1).step());
        assertEquals(ALIAS, records.getAllValues().get(1).index());
        assertEquals(50000, records.getAllValues().get(1).shipped());
    }

    /**
     * A migration interrupted after the verified copy resumes at the swap: the target is not created
     * again and the documents are not copied again.
     */
    public void testMigrationResumesAfterTheRecordedCopy() {
        doReturn(true).when(this.metadata).hasIndex(ALIAS);
        doReturn(true).when(this.routingTable).hasIndex(PHYSICAL);
        this.counts.put(ALIAS, 42L);
        this.counts.put(PHYSICAL, 42L);
        when(this.statusIndex.getIndexRecord(ALIAS))
                .thenReturn(
                        Optional.of(
                                new IndexRecord(
                                        ALIAS,
                                        0,
                                        50000,
                                        50000,
                                        SchemaStatus.REBUILD_REQUIRED,
                                        StateIndex.STEP_COPIED,
                                        Instant.now())));

        this.stateIndex.createIndex(ALIAS);

        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
        verify(this.client, never()).execute(eq(ReindexAction.INSTANCE), any());
        verify(this.indicesAdminClient).aliases(any(IndicesAliasesRequest.class));
        verify(this.statusIndex, never()).putIndexRecord(any());
    }

    /** A copy recorded complete but found short is run again before the swap. */
    public void testMigrationRepeatsAnIncompleteRecordedCopy() {
        doReturn(true).when(this.metadata).hasIndex(ALIAS);
        doReturn(true).when(this.routingTable).hasIndex(PHYSICAL);
        this.counts.put(ALIAS, 42L);
        this.counts.put(PHYSICAL, 40L);
        when(this.statusIndex.getIndexRecord(ALIAS))
                .thenReturn(
                        Optional.of(
                                new IndexRecord(
                                        ALIAS,
                                        0,
                                        50000,
                                        50000,
                                        SchemaStatus.REBUILD_REQUIRED,
                                        StateIndex.STEP_COPIED,
                                        Instant.now())));
        // The second copy completes it.
        this.stubReindex(() -> this.counts.put(PHYSICAL, 42L));

        this.stateIndex.createIndex(ALIAS);

        verify(this.client).execute(eq(ReindexAction.INSTANCE), any(ReindexRequest.class));
        verify(this.indicesAdminClient).aliases(any(IndicesAliasesRequest.class));
    }

    /** The concrete index is never replaced while the copy is short. */
    public void testMigrationKeepsTheConcreteIndexWhenTheCopyIsShort() {
        doReturn(true).when(this.metadata).hasIndex(ALIAS);
        this.counts.put(ALIAS, 42L);
        this.counts.put(PHYSICAL, 41L);

        IllegalStateException e =
                expectThrows(IllegalStateException.class, () -> this.stateIndex.migrate(ALIAS));

        assertTrue(e.getMessage(), e.getMessage().contains("copied 41 of 42 documents"));
        verify(this.indicesAdminClient, never()).aliases(any(IndicesAliasesRequest.class));
        verify(this.indicesAdminClient, never()).delete(any(DeleteIndexRequest.class));
        // The target exists, so only that step is recorded; the copy is not.
        ArgumentCaptor<IndexRecord> records = ArgumentCaptor.forClass(IndexRecord.class);
        verify(this.statusIndex).putIndexRecord(records.capture());
        assertEquals(StateIndex.STEP_TARGET_CREATED, records.getValue().step());
    }

    /** A copy that reports failures stops the migration before anything is deleted. */
    public void testMigrationStopsOnCopyFailures() {
        doReturn(true).when(this.metadata).hasIndex(ALIAS);
        BulkByScrollResponse failed = mock(BulkByScrollResponse.class);
        when(failed.getBulkFailures()).thenReturn(List.of());
        when(failed.getSearchFailures()).thenReturn(List.of());
        when(failed.isTimedOut()).thenReturn(true);
        ActionFuture<BulkByScrollResponse> future = mock(ActionFuture.class);
        doReturn(failed).when(future).actionGet(anyLong());
        doReturn(future)
                .when(this.client)
                .execute(eq(ReindexAction.INSTANCE), any(ReindexRequest.class));

        IllegalStateException e =
                expectThrows(IllegalStateException.class, () -> this.stateIndex.migrate(ALIAS));

        assertTrue(e.getMessage(), e.getMessage().contains("timed out: true"));
        verify(this.indicesAdminClient, never()).aliases(any(IndicesAliasesRequest.class));
    }

    /** Stubs a successful create index call. */
    private void stubCreate() {
        CreateIndexResponse response = mock(CreateIndexResponse.class);
        doReturn(PHYSICAL).when(response).index();
        ActionFuture<CreateIndexResponse> future = mock(ActionFuture.class);
        doReturn(response).when(future).actionGet(anyLong());
        doReturn(future).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /** Stubs the settings update, refresh, count, reindex and alias calls of a migration. */
    @SuppressWarnings("unchecked")
    private void stubMigrationCalls() {
        ActionFuture<?> acknowledged = mock(ActionFuture.class);
        doReturn(acknowledged)
                .when(this.indicesAdminClient)
                .updateSettings(any(UpdateSettingsRequest.class));
        doReturn(acknowledged).when(this.indicesAdminClient).refresh(any(RefreshRequest.class));
        doReturn(acknowledged).when(this.indicesAdminClient).aliases(any(IndicesAliasesRequest.class));

        when(this.client.search(any(SearchRequest.class)))
                .thenAnswer(
                        invocation -> {
                            String index = ((SearchRequest) invocation.getArgument(0)).indices()[0];
                            SearchResponse response = mock(SearchResponse.class);
                            when(response.getHits())
                                    .thenReturn(
                                            new SearchHits(
                                                    new SearchHit[0],
                                                    new TotalHits(
                                                            this.counts.getOrDefault(index, 0L), TotalHits.Relation.EQUAL_TO),
                                                    0f));
                            ActionFuture<SearchResponse> future = mock(ActionFuture.class);
                            doReturn(response).when(future).actionGet(anyLong());
                            return future;
                        });

        this.stubReindex(() -> {});
    }

    /** Stubs a successful reindex that runs the given side effect, e.g. to fill the target. */
    @SuppressWarnings("unchecked")
    private void stubReindex(Runnable sideEffect) {
        BulkByScrollResponse response = mock(BulkByScrollResponse.class);
        when(response.getBulkFailures()).thenReturn(List.of());
        when(response.getSearchFailures()).thenReturn(List.of());
        when(response.isTimedOut()).thenReturn(false);
        when(this.client.execute(eq(ReindexAction.INSTANCE), any(ReindexRequest.class)))
                .thenAnswer(
                        invocation -> {
                            sideEffect.run();
                            ActionFuture<BulkByScrollResponse> future = mock(ActionFuture.class);
                            doReturn(response).when(future).actionGet(anyLong());
                            return future;
                        });
    }
}
