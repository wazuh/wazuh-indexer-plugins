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

import org.junit.Before;
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

import java.lang.reflect.Field;
import java.util.Objects;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** Unit tests for the IndexStrategySelector class */
public class IndexStrategySelectorTests extends OpenSearchTestCase {

    private RoutingTable routingTable;
    private Client client;

    public void testGetIndexName() throws NoSuchFieldException, IllegalAccessException {
        for (IndexStrategySelector strategy : IndexStrategySelector.values()) {
            Field indexNameField = strategy.getClass().getDeclaredField("index");
            indexNameField.setAccessible(true);
            String indexName = (String) indexNameField.get(strategy);
            logger.info("Index name for {}: {}", strategy, indexName);
            assert indexName.equals(strategy.getIndexName());
        }
    }

    /** Test that the Ism index strategy is selected. */
    public void testInitializeIsmIndex() {
        this.routingTable = mock(RoutingTable.class);
        this.client = mock(Client.class);
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
        IsmIndexInitializer.getInstance()
            .setClient(this.client).setRoutingTable(this.routingTable);
        WazuhIndicesInitializer.getInstance()
            .setClient(this.client)
            .setRoutingTable(this.routingTable);
        IndexStrategySelector.Initializers.setIsmIndexInitializer(IsmIndexInitializer.getInstance());
        IndexStrategySelector.Initializers.setWazuhIndexInitializer(WazuhIndicesInitializer.getInstance());
        IndexStrategySelector.ISM.initIndex();
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }
}
