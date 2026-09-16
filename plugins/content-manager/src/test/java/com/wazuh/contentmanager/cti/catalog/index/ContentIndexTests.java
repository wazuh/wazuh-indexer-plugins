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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.UnavailableShardsException;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.logging.Loggers;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.breaker.CircuitBreaker;
import org.opensearch.core.common.breaker.CircuitBreakingException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.node.NodeClosedException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import com.wazuh.contentmanager.cti.catalog.model.Operation;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link ContentIndex} class. This test suite validates content index operations
 * including document creation, updates via JSON Patch operations, deletion, and retrieval.
 *
 * <p>Tests verify the correct handling of content documents, application of RFC 6902 JSON Patch
 * operations for incremental updates, and proper interaction with OpenSearch indices. Mock objects
 * simulate OpenSearch client behavior to enable testing without a live cluster.
 */
public class ContentIndexTests extends OpenSearchTestCase {

    private ContentIndex contentIndex;
    private AutoCloseable closeable;
    private Client client;
    private ObjectMapper mapper;

    @Mock private IndexResponse indexResponse;
    @Mock private GetResponse getResponse;

    private static final String INDEX_NAME = ".test-index";
    private static final String MAPPINGS_PATH = "/mappings/test-mapping.json";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        this.mapper = new ObjectMapper();

        Settings settings = Settings.builder().build();
        PluginSettings.getInstance(settings);

        this.contentIndex = new ContentIndex(this.client, INDEX_NAME, MAPPINGS_PATH);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Test creating an Integration. Validates that fields are removed during preprocessing. */
    public void testCreate_Integration_Processing() throws IOException {
        // Mock
        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);

        String jsonPayload =
                "{"
                        + "\"type\": \"integration\","
                        + "\"document\": {"
                        + "  \"id\": \"f0c91fac-d749-4ef0-bdfa-0b3632adf32d\","
                        + "  \"date\": \"2025-11-26\","
                        + "  \"kvdbs\": [],"
                        + "  \"title\": \"wazuh-fim\","
                        + "  \"author\": \"Wazuh Inc.\","
                        + "  \"category\": \"System Activity\","
                        + "  \"enable_decoders\": true"
                        + "}"
                        + "}";
        JsonNode payload = this.mapper.readTree(jsonPayload);
        String id = "f0c91fac-d749-4ef0-bdfa-0b3632adf32d";

        // Act
        this.contentIndex.create(id, payload, ActionListener.wrap(r -> {}, e -> {}));

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture(), any());

        IndexRequest request = captor.getValue();
        Assert.assertEquals(INDEX_NAME, request.index());
        Assert.assertEquals(id, request.id());

        JsonNode source = this.mapper.readTree(request.source().utf8ToString());
        JsonNode doc = source.get("document");
        Assert.assertTrue("Metadata should exist", doc.has("metadata"));
        Assert.assertTrue("Title should exist in metadata", doc.get("metadata").has("title"));
    }

    /** Test creating a Decoder. Validates that the YAML enrichment is generated. */
    /** Test creating a Decoder. Validates that the YAML enrichment is generated. */
    public void testCreate_Decoder_YamlEnrichment() throws IOException {
        // Mock
        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);

        String jsonPayload =
                "{"
                        + "\"type\": \"decoder\","
                        + "\"document\": {"
                        + "  \"id\": \"2ebb3a6b-c4a3-47fb-aae5-a0d9bd8cbfed\","
                        + "  \"name\": \"decoder/wazuh-fim/0\","
                        + "  \"check\": \"starts_with($event.original, \\\"8:syscheck:\\\")\","
                        + "  \"enabled\": true,"
                        + "  \"parents\": [\"decoder/integrations/0\"]"
                        + "}"
                        + "}";
        JsonNode payload = this.mapper.readTree(jsonPayload);
        String id = "2ebb3a6b-c4a3-47fb-aae5-a0d9bd8cbfed";

        // Act
        ContentIndex contentIndex1 =
                new ContentIndex(this.client, Constants.INDEX_DECODERS, MAPPINGS_PATH);
        contentIndex1.create(id, payload, ActionListener.wrap(r -> {}, e -> {}));

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture(), any());

        JsonNode source = this.mapper.readTree(captor.getValue().source().utf8ToString());

        Assert.assertTrue("Should contain 'yaml' field", source.has(Constants.KEY_YAML));
        String yaml = source.get(Constants.KEY_YAML).asText();
        Assert.assertTrue(yaml.contains("name: \"decoder/wazuh-fim/0\""));
        Assert.assertTrue(
                yaml.contains("check: \"starts_with($event.original, \\\"8:syscheck:\\\")\""));
    }

    /**
     * Test creating a Rule with Sigma ID. Validates that sigma_id is renamed to id in related object.
     */
    public void testCreate_Rule_SigmaIdProcessing() throws IOException {
        // Mock
        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);

        String jsonPayload =
                "{"
                        + "\"type\": \"rule\","
                        + "\"document\": {"
                        + "  \"id\": \"R1\","
                        + "  \"related\": {"
                        + "    \"sigma_id\": \"S-123\","
                        + "    \"type\": \"test-value\""
                        + "  }"
                        + "}"
                        + "}";
        JsonNode payload = this.mapper.readTree(jsonPayload);
        String id = "R1";

        // Act
        this.contentIndex.create(id, payload, ActionListener.wrap(r -> {}, e -> {}));

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture(), any());

        JsonNode source = this.mapper.readTree(captor.getValue().source().utf8ToString());
        JsonNode related = source.get("document").get("related");

        Assert.assertFalse("Should not contain sigma_id", related.has("sigma_id"));
        Assert.assertTrue("Should contain id", related.has("id"));
        Assert.assertEquals("S-123", related.get("id").asText());
    }

    /**
     * Test creating a Rule with Sigma ID in related array. Validates that sigma_id is renamed to id
     * in related array objects.
     */
    public void testCreate_Rule_SigmaIdArrayProcessing() throws IOException {
        // Mock
        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);

        String jsonPayload =
                "{"
                        + "\"type\": \"rule\","
                        + "\"document\": {"
                        + "  \"id\": \"R2\","
                        + "  \"related\": [{"
                        + "    \"sigma_id\": \"999\""
                        + "  }]"
                        + "}"
                        + "}";
        JsonNode payload = this.mapper.readTree(jsonPayload);
        String id = "R2";

        // Act
        this.contentIndex.create(id, payload, ActionListener.wrap(r -> {}, e -> {}));

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture(), any());

        JsonNode source = this.mapper.readTree(captor.getValue().source().utf8ToString());
        JsonNode relatedItem = source.get("document").get("related").get(0);

        Assert.assertFalse("Should not contain sigma_id", relatedItem.has("sigma_id"));
        Assert.assertTrue("Should contain id", relatedItem.has("id"));
        Assert.assertEquals("999", relatedItem.get("id").asText());
    }

    /**
     * Test updating a document. Simulates fetching an existing document, applying operations, and
     * re-indexing.
     */
    public void testUpdate_Operations() throws Exception {
        String id = "58dc8e10-0b69-4b81-a851-7a767e831fff";

        // Mock
        String originalDocJson =
                "{"
                        + "\"type\": \"decoder\","
                        + "\"document\": {"
                        + "  \"normalize\": [{"
                        + "    \"map\": ["
                        + "       { \"springboot.gc.last_info.time.start\": \"old_value\" }"
                        + "    ]"
                        + "  }]"
                        + "}"
                        + "}";

        PlainActionFuture<GetResponse> getFuture = PlainActionFuture.newFuture();
        getFuture.onResponse(this.getResponse);
        when(this.client.get(any(GetRequest.class))).thenReturn(getFuture);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn(originalDocJson);

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        List<Operation> operations = new ArrayList<>();
        operations.add(
                new Operation(
                        "add",
                        "/document/normalize/0/map/0/springboot.gc.last_info.time.duration",
                        null,
                        "new_duration"));

        // Act
        this.contentIndex.update(id, operations);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        JsonNode updatedDoc = this.mapper.readTree(captor.getValue().source().utf8ToString());

        JsonNode mapItem = updatedDoc.get("document").get("normalize").get(0).get("map").get(0);

        Assert.assertTrue(
                "New field should be added", mapItem.has("springboot.gc.last_info.time.duration"));
        Assert.assertEquals(
                "new_duration", mapItem.get("springboot.gc.last_info.time.duration").asText());
    }

    /** Test delete operation. */
    public void testDelete() {
        String id = "test-id";

        // Act
        this.contentIndex.delete(id);

        // Assert
        ArgumentCaptor<DeleteRequest> captor = ArgumentCaptor.forClass(DeleteRequest.class);
        verify(this.client).delete(captor.capture(), any());

        Assert.assertEquals(INDEX_NAME, captor.getValue().index());
        Assert.assertEquals(id, captor.getValue().id());
    }

    /** Test exists method when document exists. */
    public void testExists_DocumentExists() {
        // Arrange
        String id = "existing-id";
        when(this.client.prepareGet(INDEX_NAME, id).setFetchSource(false).get().isExists())
                .thenReturn(true);

        // Act
        boolean exists = this.contentIndex.exists(id);

        // Assert
        Assert.assertTrue(exists);
    }

    /** Test exists method when document does not exist. */
    public void testExists_DocumentNotExists() {
        // Arrange
        String id = "non-existing-id";
        when(this.client.prepareGet(INDEX_NAME, id).setFetchSource(false).get().isExists())
                .thenReturn(false);

        // Act
        boolean exists = this.contentIndex.exists(id);

        // Assert
        Assert.assertFalse(exists);
    }

    /** Test getIndexName method. */
    public void testGetIndexName() {
        // Act
        String indexName = this.contentIndex.getIndexName();

        // Assert
        Assert.assertEquals(INDEX_NAME, indexName);
    }

    /** Test that the default constructor sets physicalName to indexName + SUFFIX_A. */
    public void testDefaultPhysicalName() {
        ContentIndex idx = new ContentIndex(this.client, "test-alias", MAPPINGS_PATH);
        Assert.assertEquals("test-alias", idx.getIndexName());
        Assert.assertEquals("test-alias" + ContentIndex.SUFFIX_A, idx.getPhysicalName());
    }

    /** Test that the 4-arg constructor allows targeting a specific physical name. */
    public void testCustomPhysicalName() {
        ContentIndex idx = new ContentIndex(this.client, "test-alias", "test-alias-b", MAPPINGS_PATH);
        Assert.assertEquals("test-alias", idx.getIndexName());
        Assert.assertEquals("test-alias-b", idx.getPhysicalName());
    }

    /** Test that getWriteIndex returns the alias for normal (default) instances. */
    public void testGetWriteIndex_Normal() {
        ContentIndex idx = new ContentIndex(this.client, "test-alias", MAPPINGS_PATH);
        Assert.assertEquals("test-alias", idx.getWriteIndex());
    }

    /** Test that getWriteIndex returns the physical name for shadow instances. */
    public void testGetWriteIndex_Shadow() {
        ContentIndex idx = new ContentIndex(this.client, "test-alias", "test-alias-b", MAPPINGS_PATH);
        Assert.assertEquals("test-alias-b", idx.getWriteIndex());
    }

    /**
     * Regression: when a shadow swap targets the {@code -a} suffix (i.e., the live alias currently
     * points at {@code -b}), the shadow instance must still write to its physical name. Inferring
     * shadow-vs-normal from the suffix alone would incorrectly route writes through the alias and
     * land them in the old live index.
     */
    public void testGetWriteIndex_Shadow_TargetingSuffixA() {
        ContentIndex idx = new ContentIndex(this.client, "test-alias", "test-alias-a", MAPPINGS_PATH);
        Assert.assertEquals("test-alias-a", idx.getWriteIndex());
    }

    /**
     * Test that creating a resource produces the expected JSON schema. Validates that the indexed
     * document contains the required keys: document, hash, and space.
     */
    public void testCreate_Resource_ExpectedSchema() throws IOException {
        // Mock
        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);

        String jsonPayload =
                "{"
                        + "\"type\": \"test\","
                        + "\"document\": {"
                        + "  \"id\": \"test-resource-id\","
                        + "  \"title\": \"Test Resource\","
                        + "  \"enabled\": true"
                        + "}"
                        + "}";
        JsonNode payload = this.mapper.readTree(jsonPayload);
        String id = "test-resource-id";

        // Act
        this.contentIndex.create(id, payload, ActionListener.wrap(r -> {}, e -> {}));

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture(), any());

        IndexRequest request = captor.getValue();
        Assert.assertEquals(INDEX_NAME, request.index());
        Assert.assertEquals(id, request.id());

        JsonNode source = this.mapper.readTree(request.source().utf8ToString());
        Assert.assertTrue("Should contain 'document' key", source.has("document"));
        Assert.assertTrue("Should contain 'space' key", source.has("space"));
    }

    /** Test update when document does not exist. */
    public void testUpdate_DocumentNotFound() {
        // Arrange
        String id = "non-existing-id";

        PlainActionFuture<GetResponse> getFuture = PlainActionFuture.newFuture();
        getFuture.onResponse(this.getResponse);
        when(this.client.get(any(GetRequest.class))).thenReturn(getFuture);
        when(this.getResponse.isExists()).thenReturn(false);

        List<Operation> operations = new ArrayList<>();
        operations.add(new Operation("add", "/field", null, "value"));

        // Act & Assert
        Exception exception = null;
        try {
            this.contentIndex.update(id, operations);
        } catch (Exception e) {
            exception = e;
        }

        Assert.assertNotNull("Should throw exception when document not found", exception);
        Assert.assertTrue(exception.getMessage().contains("not found"));
    }

    /** Test CVE payload normalization preserves explicit top-level `type`. */
    public void testProcessPayload_CveTypeFromTopLevelType() throws IOException {
        ContentIndex cveIndex = new ContentIndex(this.client, Constants.INDEX_CVES, MAPPINGS_PATH);
        JsonNode payload =
                this.mapper.readTree("{\"type\":\"CVE\",\"document\":{\"dataType\":\"CVE_RECORD\"}}");

        JsonNode processed = cveIndex.processPayload(payload);

        Assert.assertEquals("CVE", processed.get("type").asText());
        Assert.assertEquals("CVE_RECORD", processed.get("document").get("dataType").asText());
    }

    /** Test that update with offset injects the offset value into the indexed document. */
    public void testUpdate_WithOffset() throws Exception {
        String id = "offset-test-id";
        long expectedOffset = 55L;

        // Mock - existing document
        String originalDocJson =
                "{"
                        + "\"type\": \"rule\","
                        + "\"document\": {"
                        + "  \"id\": \"R1\","
                        + "  \"title\": \"Test Rule\""
                        + "}"
                        + "}";

        PlainActionFuture<GetResponse> getFuture = PlainActionFuture.newFuture();
        getFuture.onResponse(this.getResponse);
        when(this.client.get(any(GetRequest.class))).thenReturn(getFuture);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn(originalDocJson);

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        List<Operation> operations = new ArrayList<>();
        operations.add(new Operation("replace", "/document/title", null, "Updated Rule"));

        // Act
        this.contentIndex.update(id, operations, expectedOffset);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        JsonNode updatedDoc = this.mapper.readTree(captor.getValue().source().utf8ToString());
        Assert.assertTrue("Should contain 'offset'", updatedDoc.has("offset"));
        Assert.assertEquals(expectedOffset, updatedDoc.get("offset").asLong());
    }

    /** Test that batchUpdate uses a single MultiGet + BulkRequest for multiple documents. */
    public void testBatchUpdate_MultiGetAndBulk() throws Exception {
        String doc1Json = "{\"type\":\"rule\",\"document\":{\"id\":\"R1\",\"title\":\"Rule 1\"}}";
        String doc2Json = "{\"type\":\"rule\",\"document\":{\"id\":\"R2\",\"title\":\"Rule 2\"}}";

        GetResponse getResp1 = mock(GetResponse.class);
        when(getResp1.isExists()).thenReturn(true);
        when(getResp1.getSourceAsString()).thenReturn(doc1Json);

        GetResponse getResp2 = mock(GetResponse.class);
        when(getResp2.isExists()).thenReturn(true);
        when(getResp2.getSourceAsString()).thenReturn(doc2Json);

        MultiGetItemResponse item1 = mock(MultiGetItemResponse.class);
        when(item1.isFailed()).thenReturn(false);
        when(item1.getResponse()).thenReturn(getResp1);

        MultiGetItemResponse item2 = mock(MultiGetItemResponse.class);
        when(item2.isFailed()).thenReturn(false);
        when(item2.getResponse()).thenReturn(getResp2);

        MultiGetResponse mgetResponse = mock(MultiGetResponse.class);
        when(mgetResponse.getResponses()).thenReturn(new MultiGetItemResponse[] {item1, item2});

        PlainActionFuture<MultiGetResponse> mgetFuture = PlainActionFuture.newFuture();
        mgetFuture.onResponse(mgetResponse);
        when(this.client.multiGet(any(MultiGetRequest.class))).thenReturn(mgetFuture);

        BulkResponse bulkResponse = mock(BulkResponse.class);
        when(bulkResponse.hasFailures()).thenReturn(false);

        PlainActionFuture<BulkResponse> bulkFuture = PlainActionFuture.newFuture();
        bulkFuture.onResponse(bulkResponse);
        when(this.client.bulk(any(BulkRequest.class))).thenReturn(bulkFuture);

        List<ContentIndex.UpdateTask> tasks =
                List.of(
                        new ContentIndex.UpdateTask(
                                "R1",
                                List.of(new Operation("replace", "/document/title", null, "Updated 1")),
                                101L),
                        new ContentIndex.UpdateTask(
                                "R2",
                                List.of(new Operation("replace", "/document/title", null, "Updated 2")),
                                102L));

        long result = this.contentIndex.batchUpdate(tasks);

        Assert.assertEquals(102L, result);
        verify(this.client).multiGet(any(MultiGetRequest.class));
        verify(this.client).bulk(any(BulkRequest.class));
    }

    /** Test that batchUpdate skips documents whose stored offset already matches the target. */
    public void testBatchUpdate_SkipsAlreadyAppliedOffset() throws Exception {
        String docJson =
                "{\"type\":\"rule\",\"document\":{\"id\":\"R1\",\"title\":\"Rule 1\"},\"offset\":101}";

        GetResponse getResp = mock(GetResponse.class);
        when(getResp.isExists()).thenReturn(true);
        when(getResp.getSourceAsString()).thenReturn(docJson);

        MultiGetItemResponse item = mock(MultiGetItemResponse.class);
        when(item.isFailed()).thenReturn(false);
        when(item.getResponse()).thenReturn(getResp);

        MultiGetResponse mgetResponse = mock(MultiGetResponse.class);
        when(mgetResponse.getResponses()).thenReturn(new MultiGetItemResponse[] {item});

        PlainActionFuture<MultiGetResponse> mgetFuture = PlainActionFuture.newFuture();
        mgetFuture.onResponse(mgetResponse);
        when(this.client.multiGet(any(MultiGetRequest.class))).thenReturn(mgetFuture);

        List<ContentIndex.UpdateTask> tasks =
                List.of(
                        new ContentIndex.UpdateTask(
                                "R1", List.of(new Operation("replace", "/document/title", null, "Updated")), 101L));

        long result = this.contentIndex.batchUpdate(tasks);

        Assert.assertEquals(101L, result);
        verify(this.client).multiGet(any(MultiGetRequest.class));
        verify(this.client, times(0)).bulk(any(BulkRequest.class));
    }

    /** Test that update retries on CircuitBreakingException from GET and succeeds. */
    public void testUpdate_RetriesOnCircuitBreakerException() throws Exception {
        String id = "retry-test-id";

        String originalDocJson =
                "{"
                        + "\"type\": \"rule\","
                        + "\"document\": {"
                        + "  \"id\": \"R1\","
                        + "  \"title\": \"Test Rule\""
                        + "}"
                        + "}";

        // First GET fails with CircuitBreakingException, second succeeds
        PlainActionFuture<GetResponse> failFuture = PlainActionFuture.newFuture();
        failFuture.onFailure(
                new CircuitBreakingException(
                        "Data too large", 100, 50, CircuitBreaker.Durability.TRANSIENT));

        PlainActionFuture<GetResponse> successFuture = PlainActionFuture.newFuture();
        successFuture.onResponse(this.getResponse);

        when(this.client.get(any(GetRequest.class))).thenReturn(failFuture).thenReturn(successFuture);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn(originalDocJson);

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        List<Operation> operations = new ArrayList<>();
        operations.add(new Operation("replace", "/document/title", null, "Updated"));

        this.contentIndex.update(id, operations, 10L);

        verify(this.client, times(2)).get(any(GetRequest.class));
        verify(this.client).index(any(IndexRequest.class));
    }

    // ---------------------------------------------------------------------
    // executeBulk: load shedding must be retried, never silently dropped.
    // ---------------------------------------------------------------------

    /**
     * Delays the code asked the scheduler for, in order, recorded by {@link
     * #runScheduledTasksInline()}.
     */
    private final List<Long> scheduledDelaysMs = new ArrayList<>();

    /** Makes the scheduler run the retry inline, so backoff does not slow the tests down. */
    private void runScheduledTasksInline() {
        when(this.client.threadPool().schedule(any(Runnable.class), any(TimeValue.class), anyString()))
                .thenAnswer(
                        invocation -> {
                            ContentIndexTests.this.scheduledDelaysMs.add(
                                    invocation.getArgument(1, TimeValue.class).millis());
                            invocation.getArgument(0, Runnable.class).run();
                            return null;
                        });
    }

    private static BulkResponse bulkResponseWith(BulkItemResponse... items) {
        return new BulkResponse(items, 1L);
    }

    private static BulkItemResponse successItem(int id) {
        return new BulkItemResponse(id, DocWriteRequest.OpType.INDEX, mock(IndexResponse.class));
    }

    private static BulkItemResponse shedItem(int id, String docId) {
        return new BulkItemResponse(
                id,
                DocWriteRequest.OpType.INDEX,
                new BulkItemResponse.Failure(
                        INDEX_NAME,
                        docId,
                        new CircuitBreakingException(
                                "Data too large", 100, 50, CircuitBreaker.Durability.TRANSIENT)));
    }

    private static BulkItemResponse rejectedItem(int id, String docId) {
        return new BulkItemResponse(
                id,
                DocWriteRequest.OpType.INDEX,
                new BulkItemResponse.Failure(
                        INDEX_NAME,
                        docId,
                        new IllegalArgumentException("mapper error"),
                        RestStatus.BAD_REQUEST));
    }

    private static BulkRequest bulkOf(String... ids) {
        BulkRequest request = new BulkRequest();
        for (String id : ids) {
            request.add(new IndexRequest(INDEX_NAME).id(id).source("{}", XContentType.JSON));
        }
        return request;
    }

    /** Answers client.bulk() with the given responses in order, capturing each request. */
    private List<BulkRequest> stubBulkResponses(BulkResponse... responses) {
        List<BulkRequest> captured = new ArrayList<>();
        AtomicInteger call = new AtomicInteger();
        doAnswer(
                        invocation -> {
                            captured.add(invocation.getArgument(0, BulkRequest.class));
                            int index = Math.min(call.getAndIncrement(), responses.length - 1);
                            invocation.getArgument(1, ActionListener.class).onResponse(responses[index]);
                            return null;
                        })
                .when(this.client)
                .bulk(any(BulkRequest.class), any(ActionListener.class));
        return captured;
    }

    /**
     * A circuit breaker trip is the cluster shedding load, not a bad document: only the shed item is
     * re-submitted, and nothing is reported as dropped once the retry lands.
     */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_RetriesShedItemsAndKeepsThem() throws Exception {
        this.runScheduledTasksInline();
        List<BulkRequest> sent =
                this.stubBulkResponses(
                        bulkResponseWith(successItem(0), shedItem(1, "CVE-2024-7295")),
                        bulkResponseWith(successItem(0)));

        this.contentIndex.executeBulk(bulkOf("CVE-2024-0001", "CVE-2024-7295"));

        Assert.assertEquals(2, sent.size());
        // Only the shed document is retried, not the whole batch.
        Assert.assertEquals(1, sent.get(1).numberOfActions());
        Assert.assertEquals("CVE-2024-7295", sent.get(1).requests().get(0).id());
        Assert.assertEquals(0L, this.contentIndex.getDroppedDocuments());
    }

    /** Once the retry budget is spent the documents are counted, so callers can refuse to commit. */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_CountsDroppedDocumentsWhenRetriesExhausted() throws Exception {
        this.runScheduledTasksInline();
        List<BulkRequest> sent = this.stubBulkResponses(bulkResponseWith(shedItem(0, "CVE-2024-7295")));

        this.contentIndex.executeBulk(bulkOf("CVE-2024-7295"));

        // Initial attempt plus MAX_BULK_RETRIES.
        Assert.assertEquals(4, sent.size());
        Assert.assertEquals(1L, this.contentIndex.getDroppedDocuments());
    }

    /** A rejected document is not load shedding: retrying cannot help, so it is dropped at once. */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_DoesNotRetryNonRetryableFailures() throws Exception {
        this.runScheduledTasksInline();
        List<BulkRequest> sent =
                this.stubBulkResponses(bulkResponseWith(rejectedItem(0, "CVE-2024-7295")));

        this.contentIndex.executeBulk(bulkOf("CVE-2024-7295"));

        Assert.assertEquals(1, sent.size());
        Assert.assertEquals(1L, this.contentIndex.getDroppedDocuments());
    }

    /**
     * The concurrency permit must be released on every terminal path, otherwise {@code
     * waitForPendingUpdates} deadlocks and the snapshot load never finishes.
     */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_ReleasesPermitAfterRetriesExhausted() throws Exception {
        this.runScheduledTasksInline();
        this.stubBulkResponses(bulkResponseWith(shedItem(0, "CVE-2024-7295")));

        this.contentIndex.executeBulk(bulkOf("CVE-2024-7295"));
        this.contentIndex.waitForPendingUpdates();

        Assert.assertEquals(1L, this.contentIndex.getDroppedDocuments());
    }

    /** The counter is per-load, so a fresh snapshot run starts from a clean tally. */
    @SuppressWarnings("unchecked")
    public void testResetDroppedDocuments() throws Exception {
        this.runScheduledTasksInline();
        this.stubBulkResponses(bulkResponseWith(rejectedItem(0, "CVE-2024-7295")));

        this.contentIndex.executeBulk(bulkOf("CVE-2024-7295"));
        Assert.assertEquals(1L, this.contentIndex.getDroppedDocuments());

        this.contentIndex.resetDroppedDocuments();
        Assert.assertEquals(0L, this.contentIndex.getDroppedDocuments());
    }

    // ---------------------------------------------------------------------
    // batchUpdate: the consumer sync must survive the cluster shedding a
    // write, and must never advance its offset past a document it dropped.
    // ---------------------------------------------------------------------

    private static CircuitBreakingException parentBreakerTrip() {
        return new CircuitBreakingException(
                "[parent] Data too large", 100, 50, CircuitBreaker.Durability.TRANSIENT);
    }

    /** Stubs the MultiGet that opens batchUpdate with one existing document per id. */
    private void stubMultiGet(String... ids) {
        PlainActionFuture<MultiGetResponse> future = PlainActionFuture.newFuture();
        future.onResponse(multiGetResponseFor(ids));
        when(this.client.multiGet(any(MultiGetRequest.class))).thenReturn(future);
    }

    private static MultiGetResponse multiGetResponseFor(String... ids) {
        MultiGetItemResponse[] items = new MultiGetItemResponse[ids.length];
        for (int i = 0; i < ids.length; i++) {
            GetResponse getResp = mock(GetResponse.class);
            when(getResp.isExists()).thenReturn(true);
            when(getResp.getSourceAsString())
                    .thenReturn(
                            "{\"type\":\"rule\",\"document\":{\"id\":\"" + ids[i] + "\",\"title\":\"Rule\"}}");
            MultiGetItemResponse item = mock(MultiGetItemResponse.class);
            when(item.isFailed()).thenReturn(false);
            when(item.getResponse()).thenReturn(getResp);
            items[i] = item;
        }
        MultiGetResponse mgetResponse = mock(MultiGetResponse.class);
        when(mgetResponse.getResponses()).thenReturn(items);
        return mgetResponse;
    }

    /** Answers the synchronous {@code client.bulk(request)} with the given responses, in order. */
    private List<BulkRequest> stubSyncBulkResponses(BulkResponse... responses) {
        List<BulkRequest> captured = new ArrayList<>();
        AtomicInteger call = new AtomicInteger();
        doAnswer(
                        invocation -> {
                            captured.add(invocation.getArgument(0, BulkRequest.class));
                            int index = Math.min(call.getAndIncrement(), responses.length - 1);
                            PlainActionFuture<BulkResponse> future = PlainActionFuture.newFuture();
                            future.onResponse(responses[index]);
                            return future;
                        })
                .when(this.client)
                .bulk(any(BulkRequest.class));
        return captured;
    }

    private static List<ContentIndex.UpdateTask> updateTasks(String... ids) {
        List<ContentIndex.UpdateTask> tasks = new ArrayList<>();
        for (int i = 0; i < ids.length; i++) {
            tasks.add(
                    new ContentIndex.UpdateTask(
                            ids[i],
                            List.of(new Operation("replace", "/document/title", null, "Updated")),
                            100L + i));
        }
        return tasks;
    }

    /**
     * A parent circuit breaker trip on one bulk item is the cluster shedding load, exactly as on the
     * index path: only the shed document is re-submitted and the consumer reaches its offset.
     */
    public void testBatchUpdate_RetriesShedBulkItemsAndSucceeds() throws Exception {
        this.stubMultiGet("R1", "R2");
        List<BulkRequest> sent =
                this.stubSyncBulkResponses(
                        bulkResponseWith(successItem(0), shedItem(1, "R2")), bulkResponseWith(successItem(0)));

        long result;
        try (CapturingAppender logs = CapturingAppender.attach(ContentIndex.class)) {
            result = this.contentIndex.batchUpdate(updateTasks("R1", "R2"));

            // A shed write that the retry lands is a WARN, not the ERROR that aborted the sync.
            Assert.assertEquals(1L, logs.count(Level.WARN));
            Assert.assertEquals(0L, logs.count(Level.ERROR));
        }

        Assert.assertEquals(101L, result);
        Assert.assertEquals(2, sent.size());
        // Only the shed document is retried, not the whole batch.
        Assert.assertEquals(1, sent.get(1).numberOfActions());
        Assert.assertEquals("R2", sent.get(1).requests().get(0).id());
    }

    /**
     * A rejected document is not load shedding. Retrying cannot help, and the offset must not be
     * committed, so the batch aborts and the caller checkpoints at the last applied offset.
     */
    public void testBatchUpdate_AbortsOnPermanentBulkFailure() throws Exception {
        this.stubMultiGet("R1");
        List<BulkRequest> sent = this.stubSyncBulkResponses(bulkResponseWith(rejectedItem(0, "R1")));

        IOException thrown =
                expectThrows(IOException.class, () -> this.contentIndex.batchUpdate(updateTasks("R1")));

        Assert.assertTrue(thrown.getMessage().contains("R1"));
        Assert.assertEquals(1, sent.size());
    }

    /**
     * The retry budget is finite: if the cluster is still shedding once it is spent, the batch aborts
     * rather than dropping the documents, because batchUpdate's return value is committed.
     */
    public void testBatchUpdate_AbortsWhenClusterKeepsSheddingTheBulk() throws Exception {
        this.stubMultiGet("R1");
        List<BulkRequest> sent = this.stubSyncBulkResponses(bulkResponseWith(shedItem(0, "R1")));

        IOException thrown =
                expectThrows(IOException.class, () -> this.contentIndex.batchUpdate(updateTasks("R1")));

        Assert.assertTrue(thrown.getMessage().contains("still shedding"));
        // Initial attempt plus the three retries.
        Assert.assertEquals(4, sent.size());
    }

    /**
     * The read that opens batchUpdate is shed by the same breaker as the write, and aborts the sync
     * just as readily, so it is retried too.
     */
    public void testBatchUpdate_RetriesShedMultiGet() throws Exception {
        PlainActionFuture<MultiGetResponse> shed = PlainActionFuture.newFuture();
        shed.onFailure(parentBreakerTrip());
        PlainActionFuture<MultiGetResponse> ok = PlainActionFuture.newFuture();
        ok.onResponse(multiGetResponseFor("R1"));
        when(this.client.multiGet(any(MultiGetRequest.class))).thenReturn(shed).thenReturn(ok);

        this.stubSyncBulkResponses(bulkResponseWith(successItem(0)));

        long result = this.contentIndex.batchUpdate(updateTasks("R1"));

        Assert.assertEquals(100L, result);
        verify(this.client, times(2)).multiGet(any(MultiGetRequest.class));
    }

    /**
     * A whole bulk request rejected before any item is evaluated is the same condition as a shed
     * item, and is re-submitted rather than aborting the sync.
     */
    public void testBatchUpdate_RetriesWhenWholeBulkRequestIsRejected() throws Exception {
        this.stubMultiGet("R1");

        PlainActionFuture<BulkResponse> shed = PlainActionFuture.newFuture();
        shed.onFailure(parentBreakerTrip());
        PlainActionFuture<BulkResponse> ok = PlainActionFuture.newFuture();
        ok.onResponse(bulkResponseWith(successItem(0)));
        when(this.client.bulk(any(BulkRequest.class))).thenReturn(shed).thenReturn(ok);

        long result = this.contentIndex.batchUpdate(updateTasks("R1"));

        Assert.assertEquals(100L, result);
        verify(this.client, times(2)).bulk(any(BulkRequest.class));
    }

    // ---------------------------------------------------------------------
    // A transient cluster-topology change must be retried too, and for long
    // enough to outlast a rolling restart (wazuh/wazuh-indexer#1913).
    // ---------------------------------------------------------------------

    /** An index recreated mid-load: the write resolved against a generation that no longer exists. */
    private static BulkItemResponse topologyItem(int id, String docId) {
        return new BulkItemResponse(
                id,
                DocWriteRequest.OpType.INDEX,
                new BulkItemResponse.Failure(INDEX_NAME, docId, new IndexNotFoundException(INDEX_NAME)));
    }

    /** The node holding the shard left the cluster as part of a rolling restart. */
    private static BulkItemResponse unavailableShardItem(int id, String docId) {
        return new BulkItemResponse(
                id,
                DocWriteRequest.OpType.INDEX,
                new BulkItemResponse.Failure(
                        INDEX_NAME,
                        docId,
                        new UnavailableShardsException(null, "primary shard is not active")));
    }

    /** The local node is shutting down: expected restart noise, never worth retrying. */
    private static BulkItemResponse nodeClosedItem(int id, String docId) {
        return new BulkItemResponse(
                id,
                DocWriteRequest.OpType.INDEX,
                new BulkItemResponse.Failure(INDEX_NAME, docId, mock(NodeClosedException.class)));
    }

    /** An administrative write block: a 403, which must stay permanent. */
    private static BulkItemResponse forbiddenItem(int id, String docId) {
        return new BulkItemResponse(
                id,
                DocWriteRequest.OpType.INDEX,
                new BulkItemResponse.Failure(
                        INDEX_NAME,
                        docId,
                        new IllegalStateException("index write (api)"),
                        RestStatus.FORBIDDEN));
    }

    /**
     * The #1913 case: an index recreated mid-load is transient, so the batch is re-submitted rather
     * than dropped, and the retry re-resolves the index name onto the current generation.
     */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_RetriesIndexNotFoundInsteadOfDroppingTheSnapshot() throws Exception {
        this.runScheduledTasksInline();
        List<BulkRequest> sent =
                this.stubBulkResponses(
                        bulkResponseWith(successItem(0), topologyItem(1, "IOC-2")),
                        bulkResponseWith(successItem(0)));

        this.contentIndex.executeBulk(bulkOf("IOC-1", "IOC-2"));

        Assert.assertEquals(2, sent.size());
        Assert.assertEquals(1, sent.get(1).numberOfActions());
        Assert.assertEquals("IOC-2", sent.get(1).requests().get(0).id());
        Assert.assertEquals(0L, this.contentIndex.getDroppedDocuments());
    }

    /**
     * A topology change takes as long as a node restart to settle, so its budget must outlast one.
     * The shed schedule (1 s + 2 s + 4 s) expires long before a restarted node is back.
     */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_TopologyBudgetOutlastsARollingRestart() throws Exception {
        this.runScheduledTasksInline();
        List<BulkRequest> sent =
                this.stubBulkResponses(bulkResponseWith(unavailableShardItem(0, "IOC-1")));

        this.contentIndex.executeBulk(bulkOf("IOC-1"));

        // Initial attempt plus five retries, versus four attempts for a shed write.
        Assert.assertEquals(6, sent.size());
        Assert.assertEquals(List.of(5000L, 10000L, 20000L, 30000L, 30000L), this.scheduledDelaysMs);
        Assert.assertEquals(1L, this.contentIndex.getDroppedDocuments());
    }

    /** A batch holding both kinds of failure is retried on the schedule that outlasts both. */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_MixedBatchUsesTheTopologySchedule() throws Exception {
        this.runScheduledTasksInline();
        this.stubBulkResponses(
                bulkResponseWith(shedItem(0, "IOC-1"), unavailableShardItem(1, "IOC-2")));

        this.contentIndex.executeBulk(bulkOf("IOC-1", "IOC-2"));

        Assert.assertEquals(5000L, (long) this.scheduledDelaysMs.get(0));
        Assert.assertEquals(5, this.scheduledDelaysMs.size());
    }

    /**
     * The local node shutting down is expected restart noise, not a transient topology change:
     * retrying would only burn the budget while the node goes away.
     */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_DoesNotRetryNodeClosed() throws Exception {
        this.runScheduledTasksInline();
        List<BulkRequest> sent = this.stubBulkResponses(bulkResponseWith(nodeClosedItem(0, "IOC-1")));

        this.contentIndex.executeBulk(bulkOf("IOC-1"));

        Assert.assertEquals(1, sent.size());
        Assert.assertTrue(this.scheduledDelaysMs.isEmpty());
        Assert.assertEquals(1L, this.contentIndex.getDroppedDocuments());
    }

    /**
     * A cluster block is not classified by its exception type but by its status: an administrative
     * write block reports 403 and must stay permanent, unlike the 429 a flood-stage block reports.
     */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_DoesNotRetryForbiddenClusterBlock() throws Exception {
        this.runScheduledTasksInline();
        List<BulkRequest> sent = this.stubBulkResponses(bulkResponseWith(forbiddenItem(0, "IOC-1")));

        this.contentIndex.executeBulk(bulkOf("IOC-1"));

        Assert.assertEquals(1, sent.size());
        Assert.assertEquals(1L, this.contentIndex.getDroppedDocuments());
    }

    /**
     * The transport layer clears the entries of a request it has taken over, so a retry must be
     * rebuilt from operations captured before submission. Rebuilding from the submitted instance
     * re-sends a list of nulls, which the cluster rejects with {@code No support for request [null]},
     * losing the very batch the retry exists to save.
     */
    @SuppressWarnings("unchecked")
    public void testExecuteBulk_RetrySurvivesTheTransportClearingTheRequest() throws Exception {
        this.runScheduledTasksInline();
        List<BulkRequest> sent = new ArrayList<>();
        AtomicInteger call = new AtomicInteger();
        doAnswer(
                        invocation -> {
                            BulkRequest request = invocation.getArgument(0, BulkRequest.class);
                            sent.add(request);
                            ActionListener<BulkResponse> listener =
                                    invocation.getArgument(1, ActionListener.class);
                            if (call.getAndIncrement() == 0) {
                                // What the transport does to a request it has taken over.
                                request.requests().replaceAll(operation -> null);
                                listener.onFailure(
                                        new UnavailableShardsException(null, "primary shard is not active"));
                            } else {
                                listener.onResponse(bulkResponseWith(successItem(0), successItem(1)));
                            }
                            return null;
                        })
                .when(this.client)
                .bulk(any(BulkRequest.class), any(ActionListener.class));

        this.contentIndex.executeBulk(bulkOf("IOC-1", "IOC-2"));

        Assert.assertEquals(2, sent.size());
        Assert.assertEquals(2, sent.get(1).numberOfActions());
        Assert.assertFalse(
                "the retry must not carry cleared entries", sent.get(1).requests().contains(null));
        Assert.assertEquals(0L, this.contentIndex.getDroppedDocuments());
    }

    /** The batched-update path routes a topology failure through the longer schedule as well. */
    public void testBatchUpdate_RetriesTopologyFailureOnTheLongerBudget() throws Exception {
        this.stubMultiGet("R1");
        List<BulkRequest> sent =
                this.stubSyncBulkResponses(
                        bulkResponseWith(topologyItem(0, "R1")), bulkResponseWith(successItem(0)));

        long startMs = System.currentTimeMillis();
        long result = this.contentIndex.batchUpdate(updateTasks("R1"));
        long elapsedMs = System.currentTimeMillis() - startMs;

        Assert.assertEquals(100L, result);
        Assert.assertEquals(2, sent.size());
        // The topology schedule opens at 5 s, not the shed schedule's 1 s.
        Assert.assertTrue("elapsed was " + elapsedMs + "ms", elapsedMs >= 5000);
    }

    /**
     * Collects the events a logger emits so a test can assert on the level a message was logged at.
     * {@code MockLogAppender} from the test framework is not usable here: it rewrites expected logger
     * names with an {@code org.opensearch.} prefix, so it cannot match this plugin's loggers.
     */
    private static final class CapturingAppender extends AbstractAppender implements AutoCloseable {

        private final List<LogEvent> events = new CopyOnWriteArrayList<>();
        private final Logger logger;

        private CapturingAppender(Logger logger) {
            super("capturing-" + logger.getName(), null, null, true, Property.EMPTY_ARRAY);
            this.logger = logger;
        }

        /**
         * Attaches a new appender to {@code clazz}'s logger. Close it (try-with-resources) to detach:
         * Log4j configuration is global to the JVM, so a leaked appender would follow later tests.
         */
        static CapturingAppender attach(Class<?> clazz) {
            CapturingAppender appender = new CapturingAppender(LogManager.getLogger(clazz));
            appender.start();
            Loggers.addAppender(appender.logger, appender);
            return appender;
        }

        @Override
        public void append(LogEvent event) {
            this.events.add(event.toImmutable());
        }

        long count(Level level) {
            return this.events.stream().filter(event -> event.getLevel() == level).count();
        }

        @Override
        public void close() {
            Loggers.removeAppender(this.logger, this);
            super.stop();
        }
    }
}
