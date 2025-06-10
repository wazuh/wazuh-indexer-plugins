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
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.io.IOException;

import com.wazuh.setup.utils.IndexUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class IsmIndexInitializerTests extends OpenSearchTestCase {

    private Client client;
    private RoutingTable routingTable;
    private IsmIndexInitializer ismIndexInitializer;
    private IndexUtils indexUtils;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        this.routingTable = mock(RoutingTable.class);
        this.indexUtils = mock(IndexUtils.class);
        ismIndexInitializer =
                IsmIndexInitializer.getInstance()
                        .setClient(this.client)
                        .setRoutingTable(this.routingTable)
                        .setIndexUtils(this.indexUtils);
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

        // Test when the index exists
        doReturn(true).when(this.routingTable).hasIndex(anyString());
        assert this.ismIndexInitializer.ismIndexExists(IndexStrategySelector.ISM.getIndexName());
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
