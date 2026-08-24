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

import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.util.Set;

import com.wazuh.setup.utils.JsonUtils;
import org.mockito.ArgumentCaptor;

import static org.mockito.Mockito.*;

/** Unit tests for the {@link ContentIndex} class. */
public class ContentIndexTests extends OpenSearchTestCase {

    private static final String ALIAS = "wazuh-threatintel-enrichments";
    private static final String PHYSICAL = ALIAS + ContentIndex.SUFFIX_A;

    private ContentIndex contentIndex;
    private IndicesAdminClient indicesAdminClient;
    private RoutingTable routingTable;
    private Metadata metadata;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        Client client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterService clusterService = mock(ClusterService.class);
        ClusterState clusterState = mock(ClusterState.class);
        this.routingTable = mock(RoutingTable.class);
        this.metadata = mock(Metadata.class);

        doReturn(Settings.builder().build()).when(clusterService).getSettings();

        this.contentIndex = new ContentIndex(ALIAS, "templates/content/ioc");
        this.contentIndex.setClient(client);
        this.contentIndex.setClusterService(clusterService);
        this.contentIndex.setUtils(mock(JsonUtils.class));

        doReturn(adminClient).when(client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(clusterState).when(clusterService).state();
        doReturn(this.routingTable).when(clusterState).getRoutingTable();
        doReturn(this.metadata).when(clusterState).metadata();

        // Clean cluster by default: neither the concrete index nor a squatter exists.
        doReturn(false).when(this.routingTable).hasIndex(anyString());
        doReturn(false).when(this.metadata).hasIndex(anyString());
        doReturn(false).when(this.metadata).hasAlias(anyString());
    }

    /** The concrete index is named after the alias plus the "-a" suffix. */
    public void testGetPhysicalName() {
        assertEquals(PHYSICAL, this.contentIndex.getPhysicalName());
    }

    /** On a clean cluster the "-a" index is created with the public alias as its write index. */
    public void testCreateIndexCreatesPhysicalIndexWithWriteAlias() {
        this.stubCreate(mock(CreateIndexResponse.class));

        this.contentIndex.createIndex(ALIAS);

        ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.indicesAdminClient).create(captor.capture());
        CreateIndexRequest request = captor.getValue();
        assertEquals(PHYSICAL, request.index());
        Set<Alias> aliases = request.aliases();
        assertEquals(1, aliases.size());
        Alias alias = aliases.iterator().next();
        assertEquals(ALIAS, alias.name());
        assertEquals(Boolean.TRUE, alias.writeIndex());
        verify(this.indicesAdminClient, never()).delete(any(DeleteIndexRequest.class));
    }

    /**
     * An index literally named after the alias is auto-created with dynamic mappings and occupies the
     * alias's name, so it is deleted before the "-a" index is created.
     */
    public void testCreateIndexDeletesTheIndexSquattingTheAliasName() {
        doReturn(true).when(this.metadata).hasIndex(ALIAS);
        ActionFuture<?> deleteFuture = mock(ActionFuture.class);
        doReturn(deleteFuture).when(this.indicesAdminClient).delete(any(DeleteIndexRequest.class));
        this.stubCreate(mock(CreateIndexResponse.class));

        this.contentIndex.createIndex(ALIAS);

        ArgumentCaptor<DeleteIndexRequest> captor = ArgumentCaptor.forClass(DeleteIndexRequest.class);
        verify(this.indicesAdminClient).delete(captor.capture());
        assertArrayEquals(new String[] {ALIAS}, captor.getValue().indices());
        verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /** An existing "-a" index without its alias gets the alias added rather than being recreated. */
    public void testCreateIndexAddsTheAliasWhenOnlyTheConcreteIndexExists() {
        doReturn(true).when(this.routingTable).hasIndex(PHYSICAL);
        ActionFuture<?> aliasFuture = mock(ActionFuture.class);
        doReturn(aliasFuture).when(this.indicesAdminClient).aliases(any(IndicesAliasesRequest.class));

        this.contentIndex.createIndex(ALIAS);

        ArgumentCaptor<IndicesAliasesRequest> captor =
                ArgumentCaptor.forClass(IndicesAliasesRequest.class);
        verify(this.indicesAdminClient).aliases(captor.capture());
        IndicesAliasesRequest.AliasActions action = captor.getValue().getAliasActions().get(0);
        assertArrayEquals(new String[] {PHYSICAL}, action.indices());
        assertArrayEquals(new String[] {ALIAS}, action.aliases());
        assertEquals(Boolean.TRUE, action.writeIndex());
        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
    }

    /** A fully provisioned index is left untouched. */
    public void testCreateIndexIsANoOpWhenIndexAndAliasExist() {
        doReturn(true).when(this.routingTable).hasIndex(PHYSICAL);
        doReturn(true).when(this.metadata).hasAlias(ALIAS);

        this.contentIndex.createIndex(ALIAS);

        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
        verify(this.indicesAdminClient, never()).aliases(any(IndicesAliasesRequest.class));
        verify(this.indicesAdminClient, never()).delete(any(DeleteIndexRequest.class));
    }

    /**
     * Another node winning the race to create the index is not an error, and must not trigger the
     * retry path.
     */
    public void testCreateIndexSwallowsResourceAlreadyExists() {
        ActionFuture<CreateIndexResponse> future = mock(ActionFuture.class);
        doThrow(new ResourceAlreadyExistsException("already exists")).when(future).actionGet(anyLong());
        doReturn(future).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        this.contentIndex.createIndex(ALIAS);

        verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /** Stubs a successful create index call returning the given response. */
    private void stubCreate(CreateIndexResponse response) {
        ActionFuture<CreateIndexResponse> future = mock(ActionFuture.class);
        doReturn(response).when(future).actionGet(anyLong());
        doReturn(future).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));
    }
}
