/*
 * Copyright (C) 2024, Wazuh Inc.
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

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.io.IOException;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** Tests for the IsmIndexInitializer class. */
public class IsmIndexInitializerTests extends OpenSearchTestCase {

    private Client client;
    private RoutingTable routingTable;
    private IsmIndexInitializer ismIndexInitializer;
    private IndexUtils indexUtils;
    private IndicesAdminClient indicesAdminClient;
    private ClusterService clusterService;
    private ClusterState clusterState;
    private AdminClient adminClient;

    @Override
    public void setUp() throws Exception {
        logger.info("Running setUp()");
        super.setUp();
        this.client = mock(Client.class);

        this.clusterService = mock(ClusterService.class);
        this.clusterState = mock(ClusterState.class);

        doReturn(this.clusterState).when(this.clusterService).state();

        this.routingTable = mock(RoutingTable.class);

        doReturn(this.routingTable).when(this.clusterState).getRoutingTable();

        this.indexUtils = mock(IndexUtils.class);

        this.adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        doReturn(this.adminClient).when(this.client).admin();
        doReturn(this.indicesAdminClient).when(this.adminClient).indices();

        this.ismIndexInitializer =
                IsmIndexInitializer.getInstance()
                        .setClient(this.client)
                        .setClusterService(this.clusterService)
                        .setIndexUtils(this.indexUtils);
    }

    @Override
    public void tearDown() throws Exception {
        logger.info("Running tearDown()");
        super.tearDown();
        this.client = null;
        this.clusterService = null;
        this.clusterState = null;
        this.routingTable = null;
        this.indexUtils = null;
        this.adminClient = null;
        this.indicesAdminClient = null;
        this.ismIndexInitializer = null;
    }

    /** Test the singleton instance of IsmIndexInitializer. */
    public void testGetInstance() {
        assert IsmIndexInitializer.getInstance().equals(this.ismIndexInitializer);
    }

    /** Test the check for index existence. */
    public void testIsmIndexExists() {
        // Test when the index does not exist
        doReturn(false).when(this.routingTable).hasIndex(anyString());
        assertFalse(this.ismIndexInitializer.ismIndexExists(IndexStrategySelector.ISM.getIndexName()));
    }

    /** Test the check for index existence. */
    public void testIsmIndexNotExists() {
        // Test when the index does not exist
        doReturn(false).when(this.routingTable).hasIndex(anyString());
        assertFalse(this.ismIndexInitializer.ismIndexExists(IndexStrategySelector.ISM.getIndexName()));
    }

    /** Test createIsmIndex skips creation if index already exists. */
    public void testCreateIsmIndexAlreadyExists() {
        doReturn(true).when(this.routingTable).hasIndex(anyString());
        doReturn(mock(ActionFuture.class)).when(this.client).index(any());
        doReturn(mock(ActionFuture.class))
                .when(this.indicesAdminClient)
                .create(any(CreateIndexRequest.class));
        this.ismIndexInitializer.setClusterService(this.clusterService);
        this.ismIndexInitializer.initIndex(IndexStrategySelector.ISM);
        verify(this.indicesAdminClient, never()).create(any());
    }

    /** That index is created on initialization */
    public void testInitIndexCreatesIsmIndex() {
        AdminClient adminClient = mock(AdminClient.class);
        doReturn(adminClient).when(this.client).admin();
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        doReturn(indicesAdminClient).when(adminClient).indices();
        ActionFuture<CreateIndexResponse> createIndexResponseActionFuture = mock(ActionFuture.class);
        doReturn(createIndexResponseActionFuture)
                .when(indicesAdminClient)
                .create(any(CreateIndexRequest.class));
        ActionFuture<IndexResponse> indexResponseActionFuture = mock(ActionFuture.class);
        doReturn(indexResponseActionFuture).when(this.client).index(any(IndexRequest.class));
        this.ismIndexInitializer.initIndex(IndexStrategySelector.ISM);
        verify(indicesAdminClient, times(1)).create(any(CreateIndexRequest.class));
    }

    /**
     * Test indexPolicy loads rollover policy from file and indexes it.
     *
     * @throws IOException if an error occurs while reading the policy file
     */
    public void testIndexPolicySuccess() throws IOException {
        Map<String, Object> mockPolicy = Map.of("policy", "details");

        doReturn(mockPolicy)
                .when(this.indexUtils)
                .fromFile(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID + ".json");

        doReturn(mock(ActionFuture.class)).when(this.indicesAdminClient).create(any());
        doReturn(mock(ActionFuture.class)).when(this.client).index(any(IndexRequest.class));

        this.ismIndexInitializer.initIndex(IndexStrategySelector.ISM);

        verify(this.client).index(any(IndexRequest.class));
    }

    /**
     * Test indexPolicy handles IOException while loading policy.
     *
     * @throws IOException if an error occurs while reading the policy file
     */
    public void testIndexPolicyIOException() throws IOException {
        doThrow(new IOException("File error"))
                .when(this.indexUtils)
                .fromFile(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID + ".json");

        doReturn(mock(ActionFuture.class)).when(this.indicesAdminClient).create(any());

        this.ismIndexInitializer.initIndex(IndexStrategySelector.ISM);

        verify(this.client, never()).index(any());
    }

    /**
     * Test that no action is taken if the template or policy files don't exist
     *
     * @throws IOException if an error occurs while reading the files
     */
    public void testInitIndexException() throws IOException {
        AdminClient adminClient = mock(AdminClient.class);
        doReturn(adminClient).when(this.client).admin();
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        doReturn(indicesAdminClient).when(adminClient).indices();
        ActionFuture<CreateIndexResponse> createIndexResponseActionFuture = mock(ActionFuture.class);
        doReturn(createIndexResponseActionFuture)
                .when(indicesAdminClient)
                .create(any(CreateIndexRequest.class));
        ActionFuture<IndexResponse> indexResponseActionFuture = mock(ActionFuture.class);
        doReturn(indexResponseActionFuture).when(this.client).index(any(IndexRequest.class));

        doThrow(new IOException("Error creating index")).when(indexUtils).fromFile(anyString());
        this.ismIndexInitializer.initIndex(IndexStrategySelector.ISM);
        verify(indicesAdminClient, times(0)).create(any(CreateIndexRequest.class));
        verify(this.client, times(0)).index(any(IndexRequest.class));
    }
}
