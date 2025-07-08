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

import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import com.wazuh.setup.utils.IndexUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** Unit tests for the {@link StreamIndex} class. */
public class StreamIndexTests extends OpenSearchTestCase {

    private StreamIndex streamIndex;
    private IndicesAdminClient indicesAdminClient;
    private RoutingTable routingTable;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        Client client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterService clusterService = mock(ClusterService.class);
        this.routingTable = mock(RoutingTable.class);
        ClusterState clusterState = mock(ClusterState.class);

        // Default settings
        Settings settings = Settings.builder().build();
        doReturn(settings).when(clusterService).getSettings();

        this.streamIndex = new StreamIndex("stream-index", "stream-template", "stream-alias");
        this.streamIndex.setClient(client);
        this.streamIndex.setClusterService(clusterService);
        this.streamIndex.setIndexUtils(mock(IndexUtils.class));

        doReturn(adminClient).when(client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(clusterState).when(clusterService).state();
        doReturn(this.routingTable).when(clusterState).getRoutingTable();
    }

    /**
     * Verifies that createIndex adds the alias and calls the create method when the index does not
     * exist.
     */
    public void testCreateIndexWithAlias() {
        doReturn(false).when(this.routingTable).hasIndex("stream-index");

        CreateIndexResponse response = mock(CreateIndexResponse.class);
        doReturn("stream-index").when(response).index();
        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(response).when(actionFuture).actionGet(anyLong());
        doReturn(actionFuture).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        this.streamIndex.createIndex("stream-index");

        verify(this.indicesAdminClient)
                .create(
                        argThat(
                                req -> {
                                    Alias alias = req.aliases().stream().findFirst().orElse(null);
                                    return req.index().equals("stream-index")
                                            && alias != null
                                            && "stream-alias".equals(alias.name())
                                            && Boolean.TRUE.equals(alias.writeIndex());
                                }));
    }

    /** Verifies that createIndex skips index creation if the index already exists. */
    public void testCreateIndexWhenAlreadyExists() {
        doReturn(true).when(this.routingTable).hasIndex("stream-index");

        this.streamIndex.createIndex("stream-index");

        verify(this.indicesAdminClient, never()).create(any());
    }
}
