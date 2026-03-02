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

import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import com.wazuh.setup.utils.JsonUtils;

import static org.mockito.Mockito.*;

/** Unit tests for the {@link StreamIndex} class. */
public class StreamIndexTests extends OpenSearchTestCase {

    private static final String STREAM_INDEX = "stream-index";
    private StreamIndex streamIndex;
    private IndicesAdminClient indicesAdminClient;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        Client client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterService clusterService = mock(ClusterService.class);
        RoutingTable routingTable = mock(RoutingTable.class);
        ClusterState clusterState = mock(ClusterState.class);

        // Default settings
        Settings settings = Settings.builder().build();
        doReturn(settings).when(clusterService).getSettings();

        this.streamIndex = new StreamIndex(STREAM_INDEX, "stream-template");
        this.streamIndex.setClient(client);
        this.streamIndex.setClusterService(clusterService);
        this.streamIndex.setUtils(mock(JsonUtils.class));

        doReturn(adminClient).when(client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(clusterState).when(clusterService).state();
        doReturn(routingTable).when(clusterState).getRoutingTable();
    }

    /**
     * Verifies that createIndex handles ResourceAlreadyExistsException gracefully when the data
     * stream already exists.
     */
    public void testCreateIndexWhenAlreadyExists() {
        // Mock createDataStream to throw ResourceAlreadyExistsException
        ActionFuture actionFuture = mock(ActionFuture.class);
        doThrow(new org.opensearch.ResourceAlreadyExistsException("Data stream already exists"))
                .when(actionFuture)
                .actionGet(anyLong());
        doReturn(actionFuture).when(this.indicesAdminClient).createDataStream(any());

        // Should not throw exception - it should be caught and logged
        this.streamIndex.createIndex(STREAM_INDEX);

        // Verify createDataStream was called once
        verify(this.indicesAdminClient).createDataStream(any());
    }

    /** Verifies that createIndex successfully creates a data stream when it doesn't exist. */
    public void testCreateIndexSuccess() {
        // Mock successful data stream creation
        AcknowledgedResponse response = mock(AcknowledgedResponse.class);
        //        doReturn(true).when(response).isAcknowledged();

        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(response).when(actionFuture).actionGet(anyLong());
        doReturn(actionFuture).when(this.indicesAdminClient).createDataStream(any());

        this.streamIndex.createIndex(STREAM_INDEX);

        // Verify createDataStream was called
        verify(this.indicesAdminClient).createDataStream(any());
    }
}
