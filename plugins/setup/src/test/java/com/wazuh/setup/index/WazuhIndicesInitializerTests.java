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
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.utils.IndexUtils;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** Unit tests for {@link WazuhIndicesInitializer} using {@link OpenSearchTestCase}. */
public class WazuhIndicesInitializerTests extends OpenSearchTestCase {

    private RoutingTable routingTable;
    private IndexUtils indexUtils;
    private WazuhIndicesInitializer wazuhIndicesInitializer;
    private IndicesAdminClient indicesAdminClient;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        Client client = mock(Client.class);
        ClusterService clusterService = mock(ClusterService.class);
        ClusterState clusterState = mock(ClusterState.class);
        doReturn(clusterState).when(clusterService).state();
        this.routingTable = mock(RoutingTable.class);
        doReturn(this.routingTable).when(clusterState).getRoutingTable();

        this.indexUtils = mock(IndexUtils.class);

        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        doReturn(adminClient).when(client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();

        this.wazuhIndicesInitializer =
                WazuhIndicesInitializer.getInstance()
                        .setClient(client)
                        .setClusterService(clusterService)
                        .setIndexUtils(this.indexUtils);
    }

    /** Ensures getInstance() returns a singleton. */
    public void testGetInstanceReturnsSameObject() {
        WazuhIndicesInitializer instance1 = WazuhIndicesInitializer.getInstance();
        WazuhIndicesInitializer instance2 = WazuhIndicesInitializer.getInstance();
        assertSame(instance1, instance2);
    }

    /** indexExists() returns true when the index exists. */
    public void testIndexExistsReturnsTrue() {}

    /** indexExists() returns false when the index does not exist. */
    public void testIndexExistsReturnsFalse() {
        doReturn(false).when(this.routingTable).hasIndex("test-index");
        assert (!wazuhIndicesInitializer.indexExists("test-index"));
    }

    /**
     * Tests successful template creation during initIndex().
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutTemplateCreatesSuccessfully() throws Exception {

        Map<String, Object> template =
                Map.of(
                        "mappings", Map.of("properties", Map.of()),
                        "settings", Map.of(),
                        "index_patterns", List.of("pattern-*"));

        doReturn(template).when(this.indexUtils).fromFile("template.json");
        doReturn(template.get("mappings")).when(this.indexUtils).get(template, "mappings");
        doReturn(template.get("settings")).when(this.indexUtils).get(template, "settings");

        doReturn(mock(ActionFuture.class))
                .when(this.indicesAdminClient)
                .create(any(CreateIndexRequest.class));

        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
        verify(this.indicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class));
    }

    /**
     * Handles NullPointerException during template parsing.
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutTemplateHandlesNullPointerException() throws Exception {
        doReturn(mock(ActionFuture.class)).when(this.indicesAdminClient).create(any());
        doThrow(NullPointerException.class)
                .when(this.indexUtils)
                .fromFile(IndexStrategySelector.ALERTS.getTemplateFileName());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
    }

    /**
     * Handles IOException during template reading.
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutTemplateHandlesIOException() throws Exception {
        doThrow(IOException.class)
                .when(this.indexUtils)
                .fromFile(IndexStrategySelector.ALERTS.getTemplateFileName());
        doReturn(mock(ActionFuture.class)).when(this.indicesAdminClient).create(any());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
    }

    /**
     * Handles ResourceAlreadyExistsException from putTemplate().
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutTemplateHandlesAlreadyExists() throws Exception {
        doThrow(ResourceAlreadyExistsException.class).when(this.indicesAdminClient).putTemplate(any());
        Map<String, Object> template =
                Map.of(
                        "mappings", Map.of(),
                        "settings", Map.of(),
                        "index_patterns", List.of("test-*"));
        doReturn(template).when(this.indexUtils).fromFile(anyString());
        doReturn(template.get("mappings")).when(this.indexUtils).get(template, "mappings");
        doReturn(template.get("settings")).when(this.indexUtils).get(template, "settings");
        doReturn(mock(ActionFuture.class)).when(this.indicesAdminClient).create(any());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
    }

    /** Skips index creation if it already exists. */
    public void testPutIndexSkipsIfExists() {
        doReturn(true).when(this.routingTable).hasIndex(IndexStrategySelector.ALERTS.getIndexName());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
        verify(this.indicesAdminClient, never()).create(any(CreateIndexRequest.class));
    }

    /** Creates index if it does not exist. */
    public void testPutIndexCreatesIfNotExists() {
        doReturn(false).when(this.routingTable).hasIndex(IndexStrategySelector.ALERTS.getIndexName());
        doReturn(mock(ActionFuture.class)).when(this.indicesAdminClient).create(any());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
        verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /**
     * Creates index with alias if alias is present.
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutIndexWithAlias() throws Exception {

        doReturn(false).when(this.routingTable).hasIndex("alias-index");

        IndexStrategySelector selector = IndexStrategySelector.ALERTS;

        Map<String, Object> template = Map.of("index_patterns", List.of("alias-*"));

        doReturn(template).when(this.indexUtils).fromFile(anyString());
        doReturn(Map.of()).when(this.indexUtils).get(anyMap(), eq("mappings"));
        doReturn(Map.of()).when(this.indexUtils).get(anyMap(), eq("settings"));

        doReturn(mock(ActionFuture.class))
                .when(this.indicesAdminClient)
                .create(any(CreateIndexRequest.class));

        this.wazuhIndicesInitializer.initIndex(selector);

        ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.indicesAdminClient).create(captor.capture());
        assertEquals("wazuh-alerts", captor.getValue().aliases().iterator().next().name());
    }
}
