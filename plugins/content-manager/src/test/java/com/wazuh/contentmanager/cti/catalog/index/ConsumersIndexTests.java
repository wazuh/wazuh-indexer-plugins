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

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.bulk.BulkItemResponse;
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
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.get.GetResult;
import org.opensearch.index.mapper.MapperParsingException;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;

import com.wazuh.contentmanager.cti.catalog.model.EngineLoadFailure;
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
        when(bulkResponse.getItems())
                .thenReturn(
                        new BulkItemResponse[] {
                            new BulkItemResponse(
                                    0,
                                    DocWriteRequest.OpType.INDEX,
                                    new BulkItemResponse.Failure(
                                            ConsumersIndex.INDEX_NAME,
                                            "cti:catalog:consumer:iocs",
                                            new MapperParsingException("failed to parse")))
                        });
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

    private static final String RULESET = "cti:catalog:consumer:ruleset";

    /** Failure message recorded for node 1 in the stored ruleset fixtures. */
    private static final String STORED_MESSAGE =
            "Field 'tmp_json.event.action' is not defined in WCS schema";

    /**
     * A stored ruleset document whose node 1 failed to load it, as the Engine content loader left it.
     */
    private static final String STORED_RULESET_WITH_FAILURE =
            "{\"name\":\"name\",\"context\":\"ctx\",\"type\":\"cti:catalog:consumer:ruleset\","
                    + "\"resource\":\"https://cti/ruleset\",\"is_public\":true,\"status\":\"ready\","
                    + "\"local_offset\":10,\"remote_offset\":10,\"pending_sync_phases\":[\"engine_load\"],"
                    + "\"engine_load_error\":{\"failed_at\":\"2025-11-23T06:47:12.000Z\",\"reason\":\"refused\","
                    + "\"message\":\""
                    + STORED_MESSAGE
                    + "\",\"node\":\"node-1\",\"nodes\":{\"id-1\":"
                    + "{\"failed_at\":\"2025-11-23T06:47:12.000Z\",\"reason\":\"refused\","
                    + "\"message\":\""
                    + STORED_MESSAGE
                    + "\",\"node\":\"node-1\"}}}}";

    /** A stored ruleset document with a synchronization phase pending and no Engine load failure. */
    private static final String STORED_RULESET_WITHOUT_FAILURE =
            "{\"name\":\"name\",\"context\":\"ctx\",\"type\":\"cti:catalog:consumer:ruleset\","
                    + "\"resource\":\"https://cti/ruleset\",\"is_public\":true,\"status\":\"ready\","
                    + "\"local_offset\":10,\"remote_offset\":10,\"pending_sync_phases\":[\"rules\"],"
                    + "\"updated_at\":\"2025-11-20T08:00:00.000Z\"}";

    /** Builds the get response of a stored document, read at the given sequence number and term. */
    private PlainActionFuture<GetResponse> stored(String source, long seqNo, long primaryTerm) {
        return ConsumersIndexTests.getResponse(
                new GetResult(
                        ConsumersIndex.INDEX_NAME,
                        RULESET,
                        seqNo,
                        primaryTerm,
                        1,
                        true,
                        new BytesArray(source),
                        null,
                        null));
    }

    /** Builds the get response of a document that does not exist. */
    private PlainActionFuture<GetResponse> absent() {
        return ConsumersIndexTests.getResponse(
                new GetResult(
                        ConsumersIndex.INDEX_NAME,
                        RULESET,
                        SequenceNumbers.UNASSIGNED_SEQ_NO,
                        SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
                        -1,
                        false,
                        null,
                        null,
                        null));
    }

    private static PlainActionFuture<GetResponse> getResponse(GetResult result) {
        PlainActionFuture<GetResponse> future = PlainActionFuture.newFuture();
        future.onResponse(new GetResponse(result));
        return future;
    }

    private PlainActionFuture<IndexResponse> indexed() {
        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        return future;
    }

    private PlainActionFuture<IndexResponse> conflict() {
        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onFailure(
                new VersionConflictEngineException(
                        new ShardId(ConsumersIndex.INDEX_NAME, "_na_", 0), RULESET, "seq_no mismatch"));
        return future;
    }

    private static Map<String, Object> sourceOf(IndexRequest request) {
        return XContentHelper.convertToMap(request.source(), false, XContentType.JSON).v2();
    }

    private static LocalConsumer rulesetWriter(List<String> phases) {
        return new LocalConsumer(
                "ctx",
                "name",
                RULESET,
                "https://cti/ruleset",
                true,
                LocalConsumer.Status.RUNNING,
                12L,
                20L,
                phases);
    }

    /**
     * A synchronization write of the ruleset document keeps the Engine load failure stored by the
     * Engine content loader, which the writer's own copy does not have, and is conditional on the
     * stored document not having changed since it was read.
     */
    @SuppressWarnings("unchecked")
    public void testSetConsumer_RulesetKeepsTheStoredEngineLoadFailures() throws Exception {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        when(this.client.get(any(GetRequest.class)))
                .thenReturn(this.stored(STORED_RULESET_WITH_FAILURE, 7, 2));
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexed());

        this.consumersIndex.setConsumer(ConsumersIndexTests.rulesetWriter(List.of()));

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        IndexRequest request = captor.getValue();
        Assert.assertEquals(7, request.ifSeqNo());
        Assert.assertEquals(2, request.ifPrimaryTerm());
        Map<String, Object> source = ConsumersIndexTests.sourceOf(request);
        Assert.assertEquals(12, source.get("local_offset"));
        Assert.assertEquals("running", source.get("status"));
        Assert.assertEquals(
                List.of(LocalConsumer.PHASE_ENGINE_LOAD), source.get("pending_sync_phases"));
        Map<String, Object> error = (Map<String, Object>) source.get("engine_load_error");
        Assert.assertEquals("node-1", error.get("node"));
        Assert.assertEquals(STORED_MESSAGE, error.get("message"));
        Assert.assertEquals(Set.of("id-1"), ((Map<String, Object>) error.get("nodes")).keySet());
    }

    /**
     * A writer's own copy of the Engine load state is stale by definition: the stored one wins, so a
     * write cannot bring back a failure the Engine content loader already cleared.
     */
    public void testSetConsumer_RulesetDropsTheWritersStaleFailures() throws Exception {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        when(this.client.get(any(GetRequest.class)))
                .thenReturn(this.stored(STORED_RULESET_WITHOUT_FAILURE, 3, 1));
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexed());
        LocalConsumer stale =
                ConsumersIndexTests.rulesetWriter(List.of("rules", LocalConsumer.PHASE_ENGINE_LOAD))
                        .withEngineLoadFailures(
                                Map.of(
                                        "id-1",
                                        new EngineLoadFailure(
                                                "2025-11-23T06:47:12.000Z", "refused", STORED_MESSAGE, "node-1")));

        this.consumersIndex.setConsumer(stale);

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        Map<String, Object> source = ConsumersIndexTests.sourceOf(captor.getValue());
        Assert.assertEquals(List.of("rules"), source.get("pending_sync_phases"));
        Assert.assertFalse(source.containsKey("engine_load_error"));
    }

    /**
     * When the stored document changes between the read and the write, the write is refused and made
     * again on top of the newer document, keeping the failure that document holds.
     */
    public void testSetConsumer_RulesetRetriesWhenTheStoredDocumentChanged() throws Exception {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        when(this.client.get(any(GetRequest.class)))
                .thenReturn(
                        this.stored(STORED_RULESET_WITHOUT_FAILURE, 7, 2),
                        this.stored(STORED_RULESET_WITH_FAILURE, 8, 2));
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.conflict(), this.indexed());

        this.consumersIndex.setConsumer(ConsumersIndexTests.rulesetWriter(List.of()));

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client, times(2)).index(captor.capture());
        IndexRequest retry = captor.getAllValues().get(1);
        Assert.assertEquals(8, retry.ifSeqNo());
        Assert.assertEquals(
                List.of(LocalConsumer.PHASE_ENGINE_LOAD),
                ConsumersIndexTests.sourceOf(retry).get("pending_sync_phases"));
    }

    /** A document that keeps changing under the write fails after the last attempt. */
    public void testSetConsumer_RulesetGivesUpAfterRepeatedConflicts() {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        when(this.client.get(any(GetRequest.class)))
                .thenAnswer(invocation -> this.stored(STORED_RULESET_WITHOUT_FAILURE, 7, 2));
        when(this.client.index(any(IndexRequest.class))).thenAnswer(invocation -> this.conflict());

        Assert.assertThrows(
                ExecutionException.class,
                () -> this.consumersIndex.setConsumer(ConsumersIndexTests.rulesetWriter(List.of())));

        verify(this.client, times(ConsumersIndex.MAX_WRITE_ATTEMPTS)).index(any(IndexRequest.class));
    }

    /**
     * With no stored document, the write creates it, and fails rather than replace one created
     * meanwhile.
     */
    public void testSetConsumer_RulesetCreatesTheDocumentWhenAbsent() throws Exception {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        when(this.client.get(any(GetRequest.class))).thenReturn(this.absent());
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexed());

        this.consumersIndex.setConsumer(ConsumersIndexTests.rulesetWriter(List.of("rules")));

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        Assert.assertEquals(DocWriteRequest.OpType.CREATE, captor.getValue().opType());
        Assert.assertEquals(
                List.of("rules"),
                ConsumersIndexTests.sourceOf(captor.getValue()).get("pending_sync_phases"));
    }

    /** Consumers without Engine load state keep the plain write, with no read before it. */
    public void testSetConsumer_OtherConsumersAreNotRead() throws Exception {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexed());

        this.consumersIndex.setConsumer(
                new LocalConsumer(
                        "ctx", "name", "cti:catalog:consumer:iocs", "https://cti/iocs", true, 1L, 2L));

        verify(this.client, never()).get(any(GetRequest.class));
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        Assert.assertEquals(SequenceNumbers.UNASSIGNED_SEQ_NO, captor.getValue().ifSeqNo());
    }

    /**
     * A bulk write whose ruleset item conflicts writes that document again on its own, on top of the
     * change that made it conflict.
     */
    public void testSetConsumers_RewritesTheConflictedRulesetDocument() throws Exception {
        this.mockClusterHealth(ClusterHealthStatus.GREEN);
        when(this.client.get(any(GetRequest.class)))
                .thenReturn(
                        this.stored(STORED_RULESET_WITHOUT_FAILURE, 7, 2),
                        this.stored(STORED_RULESET_WITH_FAILURE, 8, 2));
        BulkResponse bulkResponse = mock(BulkResponse.class);
        when(bulkResponse.hasFailures()).thenReturn(true);
        when(bulkResponse.getItems())
                .thenReturn(
                        new BulkItemResponse[] {
                            new BulkItemResponse(
                                    0,
                                    DocWriteRequest.OpType.INDEX,
                                    new BulkItemResponse.Failure(
                                            ConsumersIndex.INDEX_NAME,
                                            RULESET,
                                            new VersionConflictEngineException(
                                                    new ShardId(ConsumersIndex.INDEX_NAME, "_na_", 0),
                                                    RULESET,
                                                    "seq_no mismatch")))
                        });
        PlainActionFuture<BulkResponse> bulkFuture = PlainActionFuture.newFuture();
        bulkFuture.onResponse(bulkResponse);
        when(this.client.bulk(any(BulkRequest.class))).thenReturn(bulkFuture);
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexed());

        this.consumersIndex.setConsumers(List.of(ConsumersIndexTests.rulesetWriter(List.of())));

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        Assert.assertEquals(8, captor.getValue().ifSeqNo());
        Assert.assertEquals(
                List.of(LocalConsumer.PHASE_ENGINE_LOAD),
                ConsumersIndexTests.sourceOf(captor.getValue()).get("pending_sync_phases"));
    }

    /** No document, no record. */
    public void testUpdateEngineLoadFailures_AbsentDocument() throws Exception {
        when(this.client.get(any(GetRequest.class))).thenReturn(this.absent());

        Assert.assertEquals(
                ConsumersIndex.EngineLoadUpdate.ABSENT,
                this.consumersIndex.updateEngineLoadFailures(RULESET, failures -> Map.of()));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** No index yet counts as no document. */
    public void testUpdateEngineLoadFailures_MissingIndexIsAnAbsentDocument() throws Exception {
        PlainActionFuture<GetResponse> missing = PlainActionFuture.newFuture();
        missing.onFailure(new IndexNotFoundException(ConsumersIndex.INDEX_NAME));
        when(this.client.get(any(GetRequest.class))).thenReturn(missing);

        Assert.assertEquals(
                ConsumersIndex.EngineLoadUpdate.ABSENT,
                this.consumersIndex.updateEngineLoadFailures(RULESET, failures -> Map.of()));
    }

    /** A change that leaves the stored failures as they are writes nothing. */
    public void testUpdateEngineLoadFailures_UnchangedWritesNothing() throws Exception {
        when(this.client.get(any(GetRequest.class)))
                .thenReturn(this.stored(STORED_RULESET_WITH_FAILURE, 7, 2));

        Assert.assertEquals(
                ConsumersIndex.EngineLoadUpdate.UNCHANGED,
                this.consumersIndex.updateEngineLoadFailures(RULESET, failures -> new TreeMap<>(failures)));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Recording a failure changes only the Engine load state: the synchronization's fields are
     * written back as stored, conditionally, and refreshed so clients see it.
     */
    @SuppressWarnings("unchecked")
    public void testUpdateEngineLoadFailures_WritesOnlyTheFailures() throws Exception {
        when(this.client.get(any(GetRequest.class)))
                .thenReturn(this.stored(STORED_RULESET_WITHOUT_FAILURE, 3, 1));
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexed());
        EngineLoadFailure failure =
                new EngineLoadFailure("2025-11-23T06:47:12.000Z", "unreachable", "down", "node-2");

        Assert.assertEquals(
                ConsumersIndex.EngineLoadUpdate.WRITTEN,
                this.consumersIndex.updateEngineLoadFailures(RULESET, failures -> Map.of("id-2", failure)));

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        IndexRequest request = captor.getValue();
        Assert.assertEquals(3, request.ifSeqNo());
        Assert.assertEquals(1, request.ifPrimaryTerm());
        Assert.assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, request.getRefreshPolicy());
        Map<String, Object> source = ConsumersIndexTests.sourceOf(request);
        Assert.assertEquals(
                List.of("rules", LocalConsumer.PHASE_ENGINE_LOAD), source.get("pending_sync_phases"));
        Assert.assertEquals("2025-11-20T08:00:00.000Z", source.get("updated_at"));
        Assert.assertEquals(10, source.get("local_offset"));
        Assert.assertEquals(
                "unreachable", ((Map<String, Object>) source.get("engine_load_error")).get("reason"));
    }

    /**
     * A conflict reads the newer document and applies the change to it again, so another node's
     * failure recorded meanwhile is kept.
     */
    @SuppressWarnings("unchecked")
    public void testUpdateEngineLoadFailures_ReappliesTheChangeOnAConflict() throws Exception {
        when(this.client.get(any(GetRequest.class)))
                .thenReturn(
                        this.stored(STORED_RULESET_WITHOUT_FAILURE, 3, 1),
                        this.stored(STORED_RULESET_WITH_FAILURE, 4, 1));
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.conflict(), this.indexed());
        EngineLoadFailure failure =
                new EngineLoadFailure("2025-11-23T06:50:00.000Z", "unreachable", "down", "node-2");

        this.consumersIndex.updateEngineLoadFailures(
                RULESET,
                failures -> {
                    Map<String, EngineLoadFailure> updated = new TreeMap<>(failures);
                    updated.put("id-2", failure);
                    return updated;
                });

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client, times(2)).index(captor.capture());
        Map<String, Object> source = ConsumersIndexTests.sourceOf(captor.getAllValues().get(1));
        Map<String, Object> error = (Map<String, Object>) source.get("engine_load_error");
        Assert.assertEquals(
                Set.of("id-1", "id-2"), ((Map<String, Object>) error.get("nodes")).keySet());
        // node-2 failed last, so it is the one shown.
        Assert.assertEquals("node-2", error.get("node"));
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
