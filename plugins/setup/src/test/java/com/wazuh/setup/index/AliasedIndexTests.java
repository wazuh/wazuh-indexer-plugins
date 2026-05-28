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
import org.opensearch.indexmanagement.indexstatemanagement.transport.action.addpolicy.AddPolicyAction;
import org.opensearch.indexmanagement.indexstatemanagement.transport.action.addpolicy.AddPolicyRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.util.List;

import com.wazuh.setup.utils.JsonUtils;
import org.mockito.ArgumentCaptor;

import static org.mockito.Mockito.*;

/** Unit tests for the {@link AliasedIndex} class. */
public class AliasedIndexTests extends OpenSearchTestCase {

    private static final String ALIAS = "wazuh-findings-v5-security";
    private static final String EXPECTED_BACKING_INDEX = ".ds-" + ALIAS + "-000001";
    private static final String POLICY_ID = "stream-rollover-policy";

    private AliasedIndex aliasedIndex;
    private Client client;
    private IndicesAdminClient indicesAdminClient;
    private Metadata metadata;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        this.client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterService clusterService = mock(ClusterService.class);
        ClusterState clusterState = mock(ClusterState.class);
        this.metadata = mock(Metadata.class);

        // Default settings
        Settings settings = Settings.builder().build();
        doReturn(settings).when(clusterService).getSettings();

        this.aliasedIndex = new AliasedIndex(ALIAS, "templates/streams/findings", POLICY_ID);
        this.aliasedIndex.setClient(this.client);
        this.aliasedIndex.setClusterService(clusterService);
        this.aliasedIndex.setUtils(mock(JsonUtils.class));

        doReturn(adminClient).when(this.client).admin();
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
        assertNull(
                "policy_id should not be on the backing index settings — ISM ignores it for"
                        + " .ds-prefixed indices via the sweep; the attach is dispatched via"
                        + " AddPolicyAction",
                request.settings().get("plugins.index_state_management.policy_id"));

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
     * Verifies that after a successful {@code CreateIndex}, the ISM policy attach is dispatched via
     * {@link AddPolicyAction} with an {@link AddPolicyRequest} naming the backing index and the
     * configured policy id.
     */
    public void testCreateIndexDispatchesIsmAttachAfterCreate() {
        doReturn(false).when(this.metadata).hasAlias(ALIAS);

        CreateIndexResponse response = mock(CreateIndexResponse.class);
        doReturn(EXPECTED_BACKING_INDEX).when(response).index();
        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(response).when(actionFuture).actionGet(anyLong());
        doReturn(actionFuture).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        this.aliasedIndex.createIndex(ALIAS);

        ArgumentCaptor<AddPolicyRequest> reqCaptor = ArgumentCaptor.forClass(AddPolicyRequest.class);
        verify(this.client)
                .execute(same(AddPolicyAction.Companion.getINSTANCE()), reqCaptor.capture(), any());

        AddPolicyRequest sent = reqCaptor.getValue();
        assertEquals(List.of(EXPECTED_BACKING_INDEX), sent.getIndices());
        assertEquals(POLICY_ID, sent.getPolicyID());
        assertEquals("_default", sent.getIndexType());
    }

    /**
     * Verifies that an {@link AliasedIndex} created without a policy id does not invoke the ISM
     * attach call after creating the backing index.
     */
    public void testAttachPolicyIsSkippedWhenNoPolicyConfigured() {
        AliasedIndex noPolicy = new AliasedIndex(ALIAS, "templates/streams/findings");
        noPolicy.setClient(this.aliasedIndex.client);
        noPolicy.setClusterService(this.aliasedIndex.clusterService);
        noPolicy.setUtils(this.aliasedIndex.jsonUtils);

        doReturn(false).when(this.metadata).hasAlias(ALIAS);
        CreateIndexResponse response = mock(CreateIndexResponse.class);
        doReturn(EXPECTED_BACKING_INDEX).when(response).index();
        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(response).when(actionFuture).actionGet(anyLong());
        doReturn(actionFuture).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        noPolicy.createIndex(ALIAS);

        verify(this.client, never())
                .execute(same(AddPolicyAction.Companion.getINSTANCE()), any(AddPolicyRequest.class), any());
    }

    /**
     * Verifies that when the alias already exists in cluster metadata, no backing index is created
     * and no ISM attach call is made.
     */
    public void testCreateIndexSkipsWhenAliasAlreadyExists() {
        doReturn(true).when(this.metadata).hasAlias(ALIAS);

        this.aliasedIndex.createIndex(ALIAS);

        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
        verify(this.client, never())
                .execute(same(AddPolicyAction.Companion.getINSTANCE()), any(AddPolicyRequest.class), any());
    }

    /**
     * Verifies that {@code createIndex} swallows {@link ResourceAlreadyExistsException}. When the
     * create fails because the backing index is already there, the attach call is also skipped.
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
        verify(this.client, never())
                .execute(same(AddPolicyAction.Companion.getINSTANCE()), any(AddPolicyRequest.class), any());
    }
}
