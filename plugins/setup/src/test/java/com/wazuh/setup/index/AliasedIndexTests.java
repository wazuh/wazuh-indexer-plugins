/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import com.wazuh.setup.utils.JsonUtils;
import org.mockito.ArgumentCaptor;

import static org.mockito.Mockito.*;

/** Unit tests for the {@link AliasedIndex} class. */
public class AliasedIndexTests extends OpenSearchTestCase {

    private static final String ALIAS = "wazuh-findings-v5-security";
    private static final String EXPECTED_BACKING_INDEX = ".ds-" + ALIAS + "-000001";

    private AliasedIndex aliasedIndex;
    private IndicesAdminClient indicesAdminClient;
    private Metadata metadata;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        Client client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterService clusterService = mock(ClusterService.class);
        ClusterState clusterState = mock(ClusterState.class);
        this.metadata = mock(Metadata.class);

        // Default settings
        Settings settings = Settings.builder().build();
        doReturn(settings).when(clusterService).getSettings();

        this.aliasedIndex = new AliasedIndex(ALIAS, "templates/streams/findings");
        this.aliasedIndex.setClient(client);
        this.aliasedIndex.setClusterService(clusterService);
        this.aliasedIndex.setUtils(mock(JsonUtils.class));

        doReturn(adminClient).when(client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(clusterState).when(clusterService).state();
        doReturn(this.metadata).when(clusterState).getMetadata();
    }

    /**
     * Verifies that when the alias does not yet exist, the initial hidden backing index named {@code
     * .ds-<alias>-000001} is created with the alias attached as the write index.
     */
    public void testCreateIndexCreatesHiddenBackingIndexWithWriteAlias() {
        doReturn(false).when(this.metadata).hasAlias(ALIAS);

        CreateIndexResponse response = mock(CreateIndexResponse.class);
        doReturn(EXPECTED_BACKING_INDEX).when(response).index();

        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(response).when(actionFuture).actionGet(anyLong());
        doReturn(actionFuture).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        this.aliasedIndex.createIndex(ALIAS);

        ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.indicesAdminClient).create(captor.capture());

        CreateIndexRequest request = captor.getValue();
        assertEquals(EXPECTED_BACKING_INDEX, request.index());
        assertTrue(
                "Backing index must be hidden so it does not appear in wildcard queries",
                request.settings().getAsBoolean("index.hidden", false));

        assertEquals(
                "Exactly one alias must be attached to the backing index", 1, request.aliases().size());
        Alias alias = request.aliases().iterator().next();
        assertEquals(ALIAS, alias.name());
        assertEquals(
                "The alias must be marked as the write index so rollover can swap it",
                Boolean.TRUE,
                alias.writeIndex());
    }

    /**
     * Verifies that when the alias already exists in cluster metadata, no backing index is created.
     */
    public void testCreateIndexSkipsWhenAliasAlreadyExists() {
        doReturn(true).when(this.metadata).hasAlias(ALIAS);

        this.aliasedIndex.createIndex(ALIAS);

        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
    }

    /**
     * Verifies that {@code createIndex} swallows {@link ResourceAlreadyExistsException} — this can
     * happen if the backing index is created concurrently by another node between the alias check and
     * the create call.
     */
    public void testCreateIndexHandlesResourceAlreadyExists() {
        doReturn(false).when(this.metadata).hasAlias(ALIAS);

        ActionFuture actionFuture = mock(ActionFuture.class);
        doThrow(new ResourceAlreadyExistsException("Backing index already exists"))
                .when(actionFuture)
                .actionGet(anyLong());
        doReturn(actionFuture).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        // Should not throw — exception is caught and logged.
        this.aliasedIndex.createIndex(ALIAS);

        verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
    }
}
