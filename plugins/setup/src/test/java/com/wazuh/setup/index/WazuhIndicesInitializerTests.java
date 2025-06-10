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
import org.opensearch.cluster.routing.RoutingTable;
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

    private Client client;
    private RoutingTable routingTable;
    private IndexUtils indexUtils;
    private WazuhIndicesInitializer wazuhIndicesInitializer;
    private AdminClient mockAdminClient;
    private IndicesAdminClient mockIndicesClient;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        this.client = mock(Client.class);
        this.routingTable = mock(RoutingTable.class);
        this.indexUtils = mock(IndexUtils.class);

        this.mockAdminClient = mock(AdminClient.class);
        this.mockIndicesClient = mock(IndicesAdminClient.class);
        doReturn(this.mockAdminClient).when(this.client).admin();
        doReturn(this.mockIndicesClient).when(this.mockAdminClient).indices();

        this.wazuhIndicesInitializer =
                WazuhIndicesInitializer.getInstance()
                        .setClient(this.client)
                        .setRoutingTable(this.routingTable)
                        .setIndexUtils(this.indexUtils);
    }

    /** Ensures getInstance() returns a singleton. */
    public void testGetInstanceReturnsSameObject() {
        WazuhIndicesInitializer instance1 = WazuhIndicesInitializer.getInstance();
        WazuhIndicesInitializer instance2 = WazuhIndicesInitializer.getInstance();
        assertSame(instance1, instance2);
    }

    /** indexExists() returns true when the index exists. */
    public void testIndexExistsReturnsTrue() {
        RoutingTable mockRoutingTable = mock(RoutingTable.class);
        doReturn(true).when(mockRoutingTable).hasIndex("test-index");
        WazuhIndicesInitializer instance =
                WazuhIndicesInitializer.getInstance().setRoutingTable(mockRoutingTable);
        assertTrue(instance.indexExists("test-index"));
    }

    /** indexExists() returns false when the index does not exist. */
    public void testIndexExistsReturnsFalse() {
        RoutingTable mockRoutingTable = mock(RoutingTable.class);
        doReturn(false).when(mockRoutingTable).hasIndex("missing-index");
        WazuhIndicesInitializer instance =
                WazuhIndicesInitializer.getInstance().setRoutingTable(mockRoutingTable);
        assertFalse(instance.indexExists("missing-index"));
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
                .when(this.mockIndicesClient)
                .create(any(CreateIndexRequest.class));

        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
        verify(this.mockIndicesClient).putTemplate(any(PutIndexTemplateRequest.class));
    }

    /**
     * Handles NullPointerException during template parsing.
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutTemplateHandlesNullPointerException() throws Exception {
        doReturn(mock(ActionFuture.class)).when(this.mockIndicesClient).create(any());
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
        doReturn(mock(ActionFuture.class)).when(this.mockIndicesClient).create(any());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
    }

    /**
     * Handles ResourceAlreadyExistsException from putTemplate().
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutTemplateHandlesAlreadyExists() throws Exception {
        doThrow(ResourceAlreadyExistsException.class).when(this.mockIndicesClient).putTemplate(any());
        Map<String, Object> template =
                Map.of(
                        "mappings", Map.of(),
                        "settings", Map.of(),
                        "index_patterns", List.of("test-*"));
        doReturn(template).when(this.indexUtils).fromFile(anyString());
        doReturn(template.get("mappings")).when(this.indexUtils).get(template, "mappings");
        doReturn(template.get("settings")).when(this.indexUtils).get(template, "settings");
        doReturn(mock(ActionFuture.class)).when(this.mockIndicesClient).create(any());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
    }

    /** Skips index creation if it already exists. */
    public void testPutIndexSkipsIfExists() {
        doReturn(true).when(this.routingTable).hasIndex(IndexStrategySelector.ALERTS.getIndexName());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
        verify(this.mockIndicesClient, never()).create(any(CreateIndexRequest.class));
    }

    /** Creates index if it does not exist. */
    public void testPutIndexCreatesIfNotExists() {
        doReturn(false).when(this.routingTable).hasIndex(IndexStrategySelector.ALERTS.getIndexName());
        doReturn(mock(ActionFuture.class)).when(this.mockIndicesClient).create(any());
        this.wazuhIndicesInitializer.initIndex(IndexStrategySelector.ALERTS);
        verify(this.mockIndicesClient).create(any(CreateIndexRequest.class));
    }

    /**
     * Creates index with alias if alias is present.
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPutIndexWithAlias() throws Exception {
        RoutingTable mockRoutingTable = mock(RoutingTable.class);

        doReturn(false).when(mockRoutingTable).hasIndex("alias-index");

        IndexStrategySelector selector = IndexStrategySelector.ALERTS;

        IndexUtils mockUtils = mock(IndexUtils.class);
        Map<String, Object> template = Map.of("index_patterns", List.of("alias-*"));

        doReturn(template).when(mockUtils).fromFile(anyString());
        doReturn(Map.of()).when(mockUtils).get(anyMap(), eq("mappings"));
        doReturn(Map.of()).when(mockUtils).get(anyMap(), eq("settings"));

        doReturn(mock(ActionFuture.class))
                .when(this.mockIndicesClient)
                .create(any(CreateIndexRequest.class));

        this.wazuhIndicesInitializer.initIndex(selector);

        ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.mockIndicesClient).create(captor.capture());
        assertEquals("wazuh-alerts", captor.getValue().aliases().iterator().next().name());
    }
}
