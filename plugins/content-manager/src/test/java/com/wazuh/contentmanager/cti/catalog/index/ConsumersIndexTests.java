/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.index;

import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link ConsumersIndex} class. This test suite verifies the functionality of
 * consumer index operations including index creation, document storage, retrieval, and health
 * monitoring.
 *
 * <p>Tests cover scenarios such as successful index creation, consumer data persistence, retrieval
 * of consumer information, and proper handling of OpenSearch cluster health checks. Mock objects
 * are used to simulate OpenSearch client interactions without requiring a running cluster.
 */
public class ConsumersIndexTests extends OpenSearchTestCase {

    private ConsumersIndex consumersIndex;
    private AutoCloseable closeable;
    private Client client;

    @Mock private IndexResponse indexResponse;
    @Mock private GetResponse getResponse;
    @Mock private ClusterHealthResponse clusterHealthResponse;
    @Mock private IndicesExistsResponse indicesExistsResponse;
    @Mock private CreateIndexResponse createIndexResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        Settings settings = Settings.builder().build();
        PluginSettings.getInstance(settings);
        this.consumersIndex = new ConsumersIndex(this.client);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /**
     * Tests that setConsumer uses the consumer type as document ID and performs the index operation.
     *
     * @throws Exception
     */
    public void testSetConsumer_Success() throws Exception {
        // Mock
        when(this.client
                        .admin()
                        .cluster()
                        .prepareHealth()
                        .setIndices(anyString())
                        .setWaitForYellowStatus()
                        .setWaitForActiveShards(anyInt())
                        .setTimeout(any(TimeValue.class))
                        .get())
                .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(ClusterHealthStatus.GREEN);
        when(this.clusterHealthResponse.isTimedOut()).thenReturn(false);

        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);

        // Act
        LocalConsumer consumer =
                new LocalConsumer(
                        "test_context",
                        "test_consumer",
                        "cti:catalog:consumer:iocs",
                        "https://cti/iocs",
                        true,
                        100L,
                        200L);
        this.consumersIndex.setConsumer(consumer);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest request = captor.getValue();
        Assert.assertEquals(ConsumersIndex.INDEX_NAME, request.index());
        Assert.assertEquals("cti:catalog:consumer:iocs", request.id());
        // Refresh is disabled on this index, so writes must refresh immediately to avoid stale reads.
        Assert.assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, request.getRefreshPolicy());
    }

    /** Tests that setConsumer throws a RuntimeException if the cluster status is RED. */
    public void testSetConsumer_IndexNotReady() {
        // Mock
        when(this.client
                        .admin()
                        .cluster()
                        .prepareHealth()
                        .setIndices(anyString())
                        .setWaitForYellowStatus()
                        .setWaitForActiveShards(anyInt())
                        .setTimeout(any(TimeValue.class))
                        .get())
                .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(ClusterHealthStatus.RED);

        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx", "name", "cti:catalog:consumer:ruleset", "https://cti/rules", false);

        // Act and Assert
        RuntimeException ex =
                Assert.assertThrows(
                        RuntimeException.class, () -> this.consumersIndex.setConsumer(consumer));
        Assert.assertEquals("Index not ready", ex.getMessage());
    }

    /**
     * Tests that setLastCheckedAt writes the time to the catalog document, refreshing immediately.
     *
     * @throws Exception
     */
    public void testSetLastCheckedAt() throws Exception {
        // Mock
        when(this.client
                        .admin()
                        .cluster()
                        .prepareHealth()
                        .setIndices(anyString())
                        .setWaitForYellowStatus()
                        .setWaitForActiveShards(anyInt())
                        .setTimeout(any(TimeValue.class))
                        .get())
                .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(ClusterHealthStatus.GREEN);
        when(this.clusterHealthResponse.isTimedOut()).thenReturn(false);

        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);

        // Act
        this.consumersIndex.setLastCheckedAt(Instant.parse("2026-10-21T15:30:02.114Z"));

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest request = captor.getValue();
        Assert.assertEquals(ConsumersIndex.INDEX_NAME, request.index());
        Assert.assertEquals("cti:catalog:global", request.id());
        Assert.assertEquals(
                Map.of("last_checked_at", "2026-10-21T15:30:02.114Z"), request.sourceAsMap());
        Assert.assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, request.getRefreshPolicy());
    }

    /**
     * Tests getConsumer retrieves the correct document ID based on type.
     *
     * @throws Exception
     */
    public void testGetConsumer_Success() throws Exception {
        // Mock
        when(this.client
                        .admin()
                        .cluster()
                        .prepareHealth()
                        .setIndices(anyString())
                        .setWaitForYellowStatus()
                        .setWaitForActiveShards(anyInt())
                        .setTimeout(any(TimeValue.class))
                        .get())
                .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(ClusterHealthStatus.YELLOW);
        when(this.clusterHealthResponse.isTimedOut()).thenReturn(false);

        PlainActionFuture<GetResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.getResponse);
        when(this.client.get(any(GetRequest.class))).thenReturn(future);

        // Act
        this.consumersIndex.getConsumer("cti:catalog:consumer:iocs");

        // Assert
        ArgumentCaptor<GetRequest> captor = ArgumentCaptor.forClass(GetRequest.class);
        verify(this.client).get(captor.capture());

        GetRequest request = captor.getValue();
        Assert.assertEquals(ConsumersIndex.INDEX_NAME, request.index());
        Assert.assertEquals("cti:catalog:consumer:iocs", request.id());
    }

    /** Tests exists() delegates correctly to the IndicesExistsRequest. */
    public void testExists() {
        // Mock
        when(this.client.admin().indices().exists(any(IndicesExistsRequest.class)).actionGet())
                .thenReturn(this.indicesExistsResponse);
        when(this.indicesExistsResponse.isExists()).thenReturn(true);

        // Clear invocations to ensure verify only counts the actual method call
        clearInvocations(this.client.admin().indices());

        // Act
        boolean result = this.consumersIndex.exists();

        // Assert
        Assert.assertTrue(result);
        ArgumentCaptor<IndicesExistsRequest> captor =
                ArgumentCaptor.forClass(IndicesExistsRequest.class);
        verify(this.client.admin().indices()).exists(captor.capture());
        Assert.assertArrayEquals(new String[] {ConsumersIndex.INDEX_NAME}, captor.getValue().indices());
    }

    /**
     * Tests createIndex().
     *
     * @throws Exception
     */
    public void testCreateIndex() throws Exception {
        // Mock
        PlainActionFuture<CreateIndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.createIndexResponse);
        when(this.client.admin().indices().create(any(CreateIndexRequest.class))).thenReturn(future);

        ConsumersIndex spyIndex = spy(this.consumersIndex);
        doReturn("{}").when(spyIndex).loadMappingFromResources();

        // Act
        spyIndex.createIndex();

        // Assert
        ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.client.admin().indices()).create(captor.capture());

        CreateIndexRequest request = captor.getValue();
        Assert.assertEquals(ConsumersIndex.INDEX_NAME, request.index());

        // Validate Settings (Hidden = true, Replicas = 0, Codec = zstd, Refresh disabled)
        Assert.assertEquals("true", request.settings().get("hidden"));
        Assert.assertEquals("0", request.settings().get("index.number_of_replicas"));
        Assert.assertEquals("zstd", request.settings().get("index.codec"));
        Assert.assertEquals("-1", request.settings().get("index.refresh_interval"));
    }

    /**
     * Tests that getConsumer throws RuntimeException when the health check times out waiting for
     * active shards, even if the cluster status is not RED.
     */
    public void testGetConsumer_IndexNotReady_TimedOut() {
        // Mock
        when(this.client
                        .admin()
                        .cluster()
                        .prepareHealth()
                        .setIndices(anyString())
                        .setWaitForYellowStatus()
                        .setWaitForActiveShards(anyInt())
                        .setTimeout(any(TimeValue.class))
                        .get())
                .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(ClusterHealthStatus.YELLOW);
        when(this.clusterHealthResponse.isTimedOut()).thenReturn(true);

        // Act and Assert
        RuntimeException ex =
                Assert.assertThrows(
                        RuntimeException.class,
                        () -> this.consumersIndex.getConsumer("cti:catalog:consumer:ruleset"));
        Assert.assertEquals("Index not ready", ex.getMessage());
    }

    /**
     * setConsumers writes every document in one bulk request, keyed by consumer type, with a single
     * immediate refresh, so a reader sees them change together.
     *
     * @throws Exception
     */
    public void testSetConsumers_WritesAllDocumentsInOneRefreshedBulk() throws Exception {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        BulkResponse bulkResponse = mock(BulkResponse.class);
        when(bulkResponse.hasFailures()).thenReturn(false);
        PlainActionFuture<BulkResponse> future = PlainActionFuture.newFuture();
        future.onResponse(bulkResponse);
        when(this.client.bulk(any(BulkRequest.class))).thenReturn(future);

        this.consumersIndex.setConsumers(
                List.of(
                        new LocalConsumer(
                                "ctx-a", "name-a", "cti:catalog:consumer:ruleset", "https://cti/a", false, 0, 10),
                        new LocalConsumer(
                                "ctx-b", "name-b", "cti:catalog:consumer:iocs", "https://cti/b", false, 0, 20)));

        ArgumentCaptor<BulkRequest> captor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.client).bulk(captor.capture());
        BulkRequest request = captor.getValue();
        Assert.assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, request.getRefreshPolicy());
        Assert.assertEquals(2, request.numberOfActions());
        Assert.assertEquals("cti:catalog:consumer:ruleset", request.requests().get(0).id());
        Assert.assertEquals("cti:catalog:consumer:iocs", request.requests().get(1).id());
        Assert.assertEquals(ConsumersIndex.INDEX_NAME, request.requests().get(0).index());
    }

    /** setConsumers fails when any of the documents could not be written. */
    public void testSetConsumers_FailsWhenAnyDocumentFails() {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        BulkResponse bulkResponse = mock(BulkResponse.class);
        when(bulkResponse.hasFailures()).thenReturn(true);
        when(bulkResponse.buildFailureMessage()).thenReturn("failure in bulk execution");
        PlainActionFuture<BulkResponse> future = PlainActionFuture.newFuture();
        future.onResponse(bulkResponse);
        when(this.client.bulk(any(BulkRequest.class))).thenReturn(future);

        IllegalStateException ex =
                Assert.assertThrows(
                        IllegalStateException.class,
                        () ->
                                this.consumersIndex.setConsumers(
                                        List.of(
                                                new LocalConsumer(
                                                        "ctx",
                                                        "name",
                                                        "cti:catalog:consumer:iocs",
                                                        "https://cti/b",
                                                        false,
                                                        0,
                                                        20))));
        Assert.assertEquals("failure in bulk execution", ex.getMessage());
    }

    private void mockClusterHealth(ClusterHealthStatus status) {
        when(this.client
                        .admin()
                        .cluster()
                        .prepareHealth()
                        .setIndices(anyString())
                        .setWaitForYellowStatus()
                        .setWaitForActiveShards(anyInt())
                        .setTimeout(any(TimeValue.class))
                        .get())
                .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(status);
        when(this.clusterHealthResponse.isTimedOut()).thenReturn(false);
    }
}
