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

import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.model.Operation;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
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
        this.contentIndex.create(id, payload);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest request = captor.getValue();
        Assert.assertEquals(INDEX_NAME, request.index());
        Assert.assertEquals(id, request.id());

        JsonNode source = this.mapper.readTree(request.source().utf8ToString());
        JsonNode doc = source.get("document");
        Assert.assertTrue("Title should exist", doc.has("title"));
    }

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
        this.contentIndex.create(id, payload);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        JsonNode source = this.mapper.readTree(captor.getValue().source().utf8ToString());

        Assert.assertTrue("Should contain 'decoder' field", source.has("decoder"));
        String yaml = source.get("decoder").asText();
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
        this.contentIndex.create(id, payload);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

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
        this.contentIndex.create(id, payload);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

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
        this.contentIndex.create(id, payload);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest request = captor.getValue();
        Assert.assertEquals(INDEX_NAME, request.index());
        Assert.assertEquals(id, request.id());

        JsonNode source = this.mapper.readTree(request.source().utf8ToString());
        Assert.assertTrue("Should contain 'document' key", source.has("document"));
        Assert.assertTrue("Should contain 'hash' key", source.has("hash"));
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
}
