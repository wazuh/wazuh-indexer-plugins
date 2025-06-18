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

import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexUtils;

import static org.mockito.Mockito.*;

public class IndexTests extends OpenSearchTestCase {

    private Index index;
    private Client client;
    private AdminClient adminClient;
    private IndicesAdminClient indicesAdminClient;
    private ClusterService clusterService;
    private RoutingTable routingTable;
    private ClusterState clusterState;
    private IndexRoutingTable indexRoutingTable;
    private IndexUtils indexUtils;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        client = mock(Client.class);
        adminClient = mock(AdminClient.class);
        indicesAdminClient = mock(IndicesAdminClient.class);
        clusterService = mock(ClusterService.class);
        routingTable = mock(RoutingTable.class);
        clusterState = mock(ClusterState.class);
        indexRoutingTable = mock(IndexRoutingTable.class);
        indexUtils = mock(IndexUtils.class);

        // Concrete implementation of abstract class
        index = new Index("test-index", "test-template") {};
        index.setClient(client);
        index.setClusterService(clusterService);
        index.setIndexUtils(indexUtils);

        doReturn(adminClient).when(client).admin();
        doReturn(indicesAdminClient).when(adminClient).indices();
        doReturn(clusterState).when(clusterService).state();
        doReturn(routingTable).when(clusterState).getRoutingTable();
    }

    /** Verifies that index creation is attempted when index does not exist. */
    public void testCreateIndexWhenIndexDoesNotExist() {
        doReturn(false).when(routingTable).hasIndex("test-index");

        CreateIndexResponse response = mock(CreateIndexResponse.class);
        doReturn("test-index").when(response).index();
        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(response).when(actionFuture).actionGet(SetupPlugin.TIMEOUT);
        doReturn(actionFuture).when(indicesAdminClient).create(any(CreateIndexRequest.class));

        index.createIndex("test-index");

        verify(indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /** Verifies that index creation is skipped when index already exists. */
    public void testCreateIndexWhenAlreadyExists() {
        doReturn(true).when(routingTable).hasIndex("test-index");

        index.createIndex("test-index");

        verify(indicesAdminClient, never()).create(any());
    }

    /** Verifies that template creation is successful when valid data is returned from file. */
    public void testCreateTemplateSuccess() throws IOException {
        Map<String, Object> templateMap =
                Map.of(
                        "settings", Settings.builder().build(),
                        "mappings", Map.of(),
                        "index_patterns", List.of("test-*"));

        doReturn(templateMap).when(indexUtils).fromFile("test-template.json");
        doReturn(templateMap.get("mappings")).when(indexUtils).get(templateMap, "mappings");

        AcknowledgedResponse ackResponse = mock(AcknowledgedResponse.class);
        ActionFuture actionFuture = mock(ActionFuture.class);
        doReturn(ackResponse).when(actionFuture).actionGet(SetupPlugin.TIMEOUT);
        doReturn(actionFuture).when(indicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class));
        index.createTemplate("test-template");

        verify(indicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class));
    }

    /** Verifies that IOException while reading template file is caught and logged. */
    public void testCreateTemplateIOException() throws IOException {
        doThrow(new IOException("test")).when(indexUtils).fromFile("test-template.json");

        index.createTemplate("test-template");

        // Expect error to be logged but not thrown
    }

    /** Verifies that ResourceAlreadyExistsException while creating template is caught and logged. */
    public void testCreateTemplateAlreadyExists() throws IOException {
        Map<String, Object> templateMap =
                Map.of(
                        "settings", Settings.builder().build(),
                        "mappings", Map.of(),
                        "index_patterns", List.of("test-*"));

        doReturn(templateMap).when(indexUtils).fromFile("test-template.json");
        doReturn(templateMap.get("mappings")).when(indexUtils).get(templateMap, "mappings");

        doThrow(new ResourceAlreadyExistsException("already exists"))
                .when(indicesAdminClient)
                .putTemplate(any(PutIndexTemplateRequest.class));

        index.createTemplate("test-template");

        // Expect log statement but not exception
    }

    /** Verifies that initialize() invokes both createTemplate and createIndex in order. */
    public void testInitializeInvokesTemplateAndIndex() throws IOException {
        Index spyIndex = spy(index);

        doNothing().when(spyIndex).createTemplate("test-template");
        doNothing().when(spyIndex).createIndex("test-index");

        spyIndex.initialize();

        verify(spyIndex).createTemplate("test-template");
        verify(spyIndex).createIndex("test-index");
    }

    /** Verifies indexExists() returns true/false depending on cluster state. */
    public void testIndexExists() {
        doReturn(true).when(routingTable).hasIndex("test-index");
        assertTrue(index.indexExists("test-index"));

        doReturn(false).when(routingTable).hasIndex("test-index");
        assertFalse(index.indexExists("test-index"));
    }
}
