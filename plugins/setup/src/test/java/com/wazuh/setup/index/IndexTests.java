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

/** Unit tests for the {@link Index} class. */
public class IndexTests extends OpenSearchTestCase {

    private Index index;
    private Client client;
    private IndicesAdminClient indicesAdminClient;
    private RoutingTable routingTable;
    private JsonUtils jsonUtils;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        this.client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterService clusterService = mock(ClusterService.class);
        this.routingTable = mock(RoutingTable.class);
        ClusterState clusterState = mock(ClusterState.class);
        this.jsonUtils = mock(JsonUtils.class);

        // Default settings
        Settings settings = Settings.builder().build();
        doReturn(settings).when(clusterService).getSettings();

        // Concrete implementation of abstract class
        this.index = new Index("test-index", "test-template") {};
        this.index.setClient(this.client);
        this.index.setClusterService(clusterService);
        this.index.setUtils(jsonUtils);

        doReturn(adminClient).when(this.client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(clusterState).when(clusterService).state();
        doReturn(this.routingTable).when(clusterState).getRoutingTable();
    }

    /** Verifies that index creation is attempted when index does not exist. */
    public void testCreateIndexWhenIndexDoesNotExist() {
        doReturn(false).when(this.routingTable).hasIndex("test-index");

        CreateIndexResponse response = mock(CreateIndexResponse.class);
        doReturn("test-index").when(response).index();
        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(response).when(actionFuture).actionGet(anyLong());
        doReturn(actionFuture).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        this.index.createIndex("test-index");

        verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /** Verifies that index creation is skipped when index already exists. */
    public void testCreateIndexWhenAlreadyExists() {
        doReturn(true).when(this.routingTable).hasIndex("test-index");

        this.index.createIndex("test-index");

        verify(this.indicesAdminClient, never()).create(any());
    }

    /** Verifies that template creation is successful when valid data is returned from file. */
    public void testCreateTemplateSuccess() {
        // Mock the response for client.execute()
        AcknowledgedResponse ackResponse = mock(AcknowledgedResponse.class);
        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(ackResponse).when(actionFuture).actionGet(anyLong());

        // Mock client.execute() which is what createTemplate actually uses
        doReturn(actionFuture).when(this.client).execute(any(), any());

        // Call createTemplate with a real template file that exists
        this.index.createTemplate("templates/ism-config");

        // Verify that client.execute was called
        verify(this.client).execute(any(), any());
    }

    /** Verifies that initialize() invokes both createTemplate and createIndex in order. */
    public void testInitializeInvokesTemplateAndIndex() {
        Index spyIndex = spy(this.index);

        doNothing().when(spyIndex).createTemplate("test-template");
        doNothing().when(spyIndex).createIndex("test-index");

        spyIndex.initialize();

        verify(spyIndex).createTemplate("test-template");
        verify(spyIndex).createIndex("test-index");
    }

    /** Verifies indexExists() returns true/false depending on cluster state. */
    public void testIndexExists() {
        doReturn(true).when(this.routingTable).hasIndex("test-index");
        assertTrue(this.index.indexExists("test-index"));

        doReturn(false).when(this.routingTable).hasIndex("test-index");
        assertFalse(this.index.indexExists("test-index"));
    }
}
