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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link StateIndex}: the alias topology on a fresh cluster, and what is done with a
 * concrete index found at the alias name.
 */
public class StateIndexTests extends OpenSearchTestCase {

    private static final String ALIAS = "wazuh-states-sca";
    private static final String PHYSICAL = ALIAS + AliasedIndex.SUFFIX_A;

    private StateIndex stateIndex;
    private Client client;
    private IndicesAdminClient indicesAdminClient;
    private Metadata metadata;

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
        RoutingTable routingTable = mock(RoutingTable.class);
        this.metadata = mock(Metadata.class);

        doReturn(Settings.builder().build()).when(clusterService).getSettings();

        this.stateIndex = new StateIndex(ALIAS, "templates/states/sca");
        this.stateIndex.setClient(this.client);
        this.stateIndex.setClusterService(clusterService);

        doReturn(adminClient).when(this.client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(clusterState).when(clusterService).state();
        doReturn(routingTable).when(clusterState).getRoutingTable();
        doReturn(this.metadata).when(clusterState).metadata();
        doReturn(new TreeMap<>()).when(this.metadata).getIndicesLookup();

        // Clean cluster by default: neither the concrete index nor the alias exists.
        doReturn(false).when(routingTable).hasIndex(anyString());
        doReturn(false).when(this.metadata).hasIndex(anyString());
        doReturn(false).when(this.metadata).hasAlias(anyString());

        this.stubCreate();
        this.stubCount();
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
        verify(this.indicesAdminClient, never()).delete(any(DeleteIndexRequest.class));
    }

    /** With the alias on the alternate slot and no "-a" index, nothing is done. */
    public void testCreateIndexIsANoOpWhenTheAliasPointsAtTheAlternateSlot() {
        doReturn(true).when(this.metadata).hasAlias(ALIAS);

        this.stateIndex.createIndex(ALIAS);

        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
        verify(this.indicesAdminClient, never()).aliases(any(IndicesAliasesRequest.class));
        verify(this.indicesAdminClient, never()).delete(any(DeleteIndexRequest.class));
    }

    /** The template patterns cover both physical slots and the alias name. */
    public void testTemplateCoversEverySlot() throws Exception {
        com.wazuh.setup.model.IndexTemplate template = this.stateIndex.loadTemplate();

        this.stateIndex.customizeTemplate(template);

        assertEquals(List.of(ALIAS + "*"), template.getIndexPatterns());
        assertEquals("states-sca", this.stateIndex.templateName("templates/states/sca"));
    }

    /** An empty concrete index at the alias name is deleted, then "-a" is created with the alias. */
    public void testCreateIndexDeletesAnEmptyConcreteIndex() {
        doReturn(true).when(this.metadata).hasIndex(ALIAS);
        this.counts.put(ALIAS, 0L);

        this.stateIndex.createIndex(ALIAS);

        ArgumentCaptor<DeleteIndexRequest> delete = ArgumentCaptor.forClass(DeleteIndexRequest.class);
        verify(this.indicesAdminClient).delete(delete.capture());
        assertArrayEquals(new String[] {ALIAS}, delete.getValue().indices());

        ArgumentCaptor<CreateIndexRequest> create = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.indicesAdminClient).create(create.capture());
        assertEquals(PHYSICAL, create.getValue().index());
        assertEquals(ALIAS, create.getValue().aliases().iterator().next().name());

        InOrder order = inOrder(this.indicesAdminClient);
        order.verify(this.indicesAdminClient).delete(any(DeleteIndexRequest.class));
        order.verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /** A concrete index at the alias name that holds documents is kept, and the creation fails. */
    public void testCreateIndexFailsOnAPopulatedConcreteIndex() {
        doReturn(true).when(this.metadata).hasIndex(ALIAS);
        this.counts.put(ALIAS, 42L);

        IllegalStateException e =
                expectThrows(IllegalStateException.class, () -> this.stateIndex.createIndex(ALIAS));

        assertTrue(e.getMessage(), e.getMessage().contains("[" + ALIAS + "]"));
        assertTrue(e.getMessage(), e.getMessage().contains("42 documents"));
        verify(this.indicesAdminClient, never()).delete(any(DeleteIndexRequest.class));
        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
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

    /** Stubs the refresh, count and delete calls, the count answering from {@link #counts}. */
    @SuppressWarnings("unchecked")
    private void stubCount() {
        ActionFuture<?> acknowledged = mock(ActionFuture.class);
        doReturn(acknowledged).when(this.indicesAdminClient).refresh(any(RefreshRequest.class));
        doReturn(acknowledged).when(this.indicesAdminClient).delete(any(DeleteIndexRequest.class));

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
    }
}
