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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** Unit tests for the IndexStrategySelector class */
public class IndexStrategySelectorTests extends OpenSearchTestCase {

    private Client client;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        RoutingTable routingTable = mock(RoutingTable.class);
        this.client = mock(Client.class);

        AdminClient adminClient = mock(AdminClient.class);
        doReturn(adminClient).when(this.client).admin();
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        doReturn(indicesAdminClient).when(adminClient).indices();
        ActionFuture<CreateIndexResponse> createIndexResponseActionFuture = mock(ActionFuture.class);

        ClusterService clusterService = mock(ClusterService.class);
        ClusterState clusterState = mock(ClusterState.class);
        doReturn(clusterState).when(clusterService).state();
        doReturn(routingTable).when(clusterState).getRoutingTable();

        routingTable = mock(RoutingTable.class);
        doReturn(routingTable).when(clusterState).getRoutingTable();

        doReturn(createIndexResponseActionFuture)
                .when(indicesAdminClient)
                .create(any(CreateIndexRequest.class));
        ActionFuture<IndexResponse> indexResponseActionFuture = mock(ActionFuture.class);
        doReturn(indexResponseActionFuture).when(this.client).index(any(IndexRequest.class));

        IndexStrategySelector.Initializers.setup(this.client, clusterService);
    }

    /** Tests the initialization of indices for each strategy in IndexStrategySelector. */
    public void testInitIndices() {
        for (IndexStrategySelector strategy : IndexStrategySelector.values()) {
            strategy.initIndex();
            verify(this.client, times(1)).index(any(IndexRequest.class));
        }
    }
}
