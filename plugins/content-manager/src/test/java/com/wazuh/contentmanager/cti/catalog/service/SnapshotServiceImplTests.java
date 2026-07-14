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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.wazuh.contentmanager.cti.catalog.client.SnapshotClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Cve;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link SnapshotServiceImpl} class. This test suite validates the snapshot
 * synchronization service responsible for downloading, extracting, and indexing CTI catalog
 * snapshots.
 *
 * <p>Tests cover snapshot download and extraction, bulk indexing of catalog content, consumer state
 * persistence, error handling for corrupted snapshots, and proper cleanup of temporary files. Mock
 * objects simulate snapshot client interactions and OpenSearch operations without requiring network
 * access or a running cluster.
 */
public class SnapshotServiceImplTests extends OpenSearchTestCase {

    /** Mirrors {@code SnapshotServiceImpl.mapper} (plain, no BigDecimal). */
    private final ObjectMapper plain = new ObjectMapper();

    /** Mirrors {@code ContentIndex.mapper} (BigDecimal for floats). */
    private final ObjectMapper cti =
            new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    private SnapshotServiceImpl snapshotService;
    private Path tempDir;

    @Mock private SnapshotClient snapshotClient;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private ContentIndex contentIndexMock;
    @Mock private Environment environment;
    @Mock private RemoteConsumer remoteConsumer;

    private AutoCloseable closeable;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.tempDir = OpenSearchTestCase.createTempDir();

        // Setup Environment mock to return our temp dir
        Settings settings = Settings.builder().put("path.home", this.tempDir.toString()).build();
        when(this.environment.tmpDir()).thenReturn(this.tempDir);
        when(this.environment.settings()).thenReturn(settings);

        PluginSettings.getInstance(settings);

        Map<String, ContentIndex> indicesMap = new HashMap<>();
        indicesMap.put("kvdb", this.contentIndexMock);
        indicesMap.put("policy", this.contentIndexMock);
        indicesMap.put("decoder", this.contentIndexMock);
        indicesMap.put("rule", this.contentIndexMock);
        indicesMap.put("reputation", this.contentIndexMock);

        this.snapshotService =
                new SnapshotServiceImpl(
                        "cti:catalog:consumer:ruleset", indicesMap, this.consumersIndex, this.environment);
        this.snapshotService.setSnapshotClient(this.snapshotClient);

        // Updated matchers to use JsonNode instead of JsonObject
        when(this.contentIndexMock.processPayload(any(JsonNode.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(this.contentIndexMock.getWriteIndex()).thenReturn(".test-context-test-consumer-kvdb");
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
     * Tests that the initialization aborts gracefully if the snapshot URL is missing.
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    public void testInitialize_EmptyUrl() throws IOException, URISyntaxException {
        when(this.remoteConsumer.getSnapshotLink()).thenReturn("");

        this.snapshotService.initialize(this.remoteConsumer);

        verify(this.snapshotClient, never()).downloadFile(anyString());
        verify(this.contentIndexMock, never()).clear();
    }

    /**
     * Tests that the initialization aborts if the download fails (returns null).
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    public void testInitialize_DownloadFails() throws IOException, URISyntaxException {
        String url = "http://example.com/snapshot.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);
        when(this.snapshotClient.downloadFile(url)).thenReturn(null);

        this.snapshotService.initialize(this.remoteConsumer);

        verify(this.snapshotClient).downloadFile(url);
        verify(this.contentIndexMock, never()).clear();
    }

    /**
     * Tests a successful initialization flow: 1. Download succeeds. 2. ZIP entries are streamed and
     * parsed. 3. Consumer index is updated (check using the local consumer)
     *
     * @throws TimeoutException
     * @throws ExecutionException
     * @throws URISyntaxException
     * @throws InterruptedException
     * @throws IOException
     */
    public void testInitialize_Success()
            throws IOException,
                    ExecutionException,
                    InterruptedException,
                    TimeoutException,
                    URISyntaxException {
        // Mock
        String url = "http://example.com/snapshot.zip";
        long offset = 100L;
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);
        when(this.remoteConsumer.getOffset()).thenReturn(offset);
        when(this.remoteConsumer.getSnapshotOffset()).thenReturn(offset);

        // Pre-existing t0 consumer doc (written by AbstractConsumerService.writeInitialConsumer
        // before initialize runs). SnapshotServiceImpl reads this back to perform a partial update
        // of local_offset.
        String existingConsumerJson =
                "{\"name\":\"test-consumer\",\"context\":\"test-context\","
                        + "\"type\":\"cti:catalog:consumer:ruleset\","
                        + "\"resource\":\"https://cti.example/catalog/contexts/test-context/consumers/test-consumer\","
                        + "\"is_public\":true,\"status\":\"running\",\"local_offset\":0,\"remote_offset\":100}";
        org.opensearch.action.get.GetResponse t0Response =
                mock(org.opensearch.action.get.GetResponse.class);
        when(t0Response.isExists()).thenReturn(true);
        when(t0Response.getSourceAsString()).thenReturn(existingConsumerJson);
        when(this.consumersIndex.getConsumer("cti:catalog:consumer:ruleset")).thenReturn(t0Response);

        Path zipPath =
                this.createZipFileWithContent(
                        "data.json",
                        "{\"name\": \"12345678\", \"offset\": 1, \"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"12345678\", \"title\": \"Test Kvdb\"}}}");
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock, never()).clear();
        verify(this.contentIndexMock).processPayload(any(JsonNode.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        BulkRequest request = bulkCaptor.getValue();
        Assert.assertEquals(1, request.numberOfActions());
        IndexRequest indexRequest = (IndexRequest) request.requests().getFirst();

        Assert.assertEquals(".test-context-test-consumer-kvdb", indexRequest.index());
        Assert.assertEquals("12345678", indexRequest.id());

        // Verify waiting for pending updates
        verify(this.contentIndexMock).waitForPendingUpdates();

        // After load, only local_offset is updated; identity fields and remote_offset are
        // preserved from the pre-existing (t0-written) document.
        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());
        LocalConsumer persisted = consumerCaptor.getValue();
        Assert.assertEquals(offset, persisted.getLocalOffset());
        Assert.assertEquals(100L, persisted.getRemoteOffset());
        Assert.assertEquals("test-consumer", persisted.getName());
        Assert.assertEquals("test-context", persisted.getContext());
        Assert.assertEquals("cti:catalog:consumer:ruleset", persisted.getType());
        Assert.assertTrue(persisted.isPublic());
        Assert.assertEquals(LocalConsumer.Status.RUNNING, persisted.getStatus());
    }

    /**
     * Tests that documents with type "policy" are indexed correctly.
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    public void testInitialize_IndexesPolicyType() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/policy.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);
        when(this.contentIndexMock.getWriteIndex()).thenReturn(".test-context-test-consumer-policy");

        Path zipPath =
                this.createZipFileWithContent(
                        "policy.json",
                        "{\"name\": \"123\", \"offset\": 1, \"payload\": {\"type\": \"policy\", \"document\": {\"id\": \"123\"}}}");
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonNode.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock).executeBulk(bulkCaptor.capture());

        IndexRequest request = (IndexRequest) bulkCaptor.getValue().requests().getFirst();

        Assert.assertEquals(".test-context-test-consumer-policy", request.index());
        Assert.assertEquals("123", request.id());
    }

    /**
     * Tests that type "decoder" documents are delegated to ContentIndex for processing.
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    public void testInitialize_EnrichDecoderWithYaml() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/decoder.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent =
                "{\"name\": \"123\", \"offset\": 1, \"payload\": {\"type\": \"decoder\", \"document\": {\"name\": \"syslog\", \"parent\": \"root\"}}}";
        Path zipPath = this.createZipFileWithContent("decoder.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        // Verify delegation to ContentIndex.processPayload
        verify(this.contentIndexMock).processPayload(any(JsonNode.class));
        verify(this.contentIndexMock).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests preprocessing: Verifies that payload processing is delegated.
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    public void testInitialize_PreprocessSigmaId() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/sigma.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent =
                "{\"name\": \"123\", \"offset\": 1, \"payload\": {\"type\": \"rule\", \"document\": {\"id\": \"R1\", \"related\": {\"sigma_id\": \"S-123\", \"type\": \"test-value\"}}}}";
        Path zipPath = this.createZipFileWithContent("sigma.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonNode.class));
        verify(this.contentIndexMock).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests that files without 'payload', 'type', or 'document' are skipped.
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    public void testInitialize_InvalidJsonStructure() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/invalid.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{}\n" + "{\"payload\": {}}";

        Path zipPath = this.createZipFileWithContent("invalid.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock, never()).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests preprocessing with related array: Verifies that payload processing is delegated.
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    public void testInitialize_PreprocessSigmaIdInArray() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/sigma_array.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent =
                "{\"name\": \"123\", \"offset\": 1, \"payload\": {\"type\": \"rule\", \"document\": {\"id\": \"R2\", \"related\": [{\"sigma_id\": \"999\"}]}}}";
        Path zipPath = this.createZipFileWithContent("sigma_array.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonNode.class));
        verify(this.contentIndexMock).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests that if a file contains a mix of valid JSON and corrupt lines (parsing errors), the
     * service logs the error, skips the bad line, and continues indexing the valid ones.
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    public void testInitialize_SkipInvalidJson() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/corrupt.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        // spotless:off
        String jsonContent =
            """
                {"name": "123", "offset": 1, "payload": {"type": "reputation", "document": {"id": "1", "ip": "1.1.1.1"}}}
                THIS_IS_NOT_JSON_{{}}
                {"name": "123", "offset": 1, "payload": {"type": "reputation", "document": {"id": "2", "ip": "2.2.2.2"}}}""";
        // spotless:on
        Path zipPath = this.createZipFileWithContent("mixed.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock, atLeastOnce()).processPayload(any(JsonNode.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        // We expect exactly 2 valid actions (Line 1 and Line 3), skipping Line 2
        int totalActions =
                bulkCaptor.getAllValues().stream().mapToInt(BulkRequest::numberOfActions).sum();

        Assert.assertEquals(
                "Should index the 2 valid documents and skip the corrupt one", 2, totalActions);
    }

    /**
     * Tests delegation for decoder YAML processing.
     *
     * @throws IOException
     * @throws URISyntaxException
     */
    public void testInitialize_DecoderYamlDelegation() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/decoder_order.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent =
                "{\"name\": \"123\", \"offset\": 1, \"payload\": {\"type\": \"decoder\", \"document\": "
                        + "{\"check\": \"some_regex\", \"name\": \"ssh-decoder\", \"parents\": [\"root\"]}}}";

        Path zipPath = this.createZipFileWithContent("decoder_order.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonNode.class));
        verify(this.contentIndexMock).executeBulk(any(BulkRequest.class));
    }

    /** Tests that CVE resources are identified from the root `resource` field and indexed as CVEs. */
    public void testInitialize_IndexesCveByResourceField() throws Exception {
        String url = "http://example.com/cve.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        Map<String, ContentIndex> cveOnlyMap = new HashMap<>();
        cveOnlyMap.put("cves", this.contentIndexMock);

        SnapshotServiceImpl cveSnapshotService =
                new SnapshotServiceImpl(
                        "cti:catalog:consumer:vulnerabilities",
                        cveOnlyMap,
                        this.consumersIndex,
                        this.environment);
        cveSnapshotService.setSnapshotClient(this.snapshotClient);

        when(this.contentIndexMock.getWriteIndex()).thenReturn(".wazuh-threatintel-vulnerabilities");

        Path zipPath =
                this.createZipFileWithContent(
                        "cve.json",
                        "{\"resource\": \"TID-123\", \"offset\": 1, \"payload\": {\"document\": {\"foo\": \"bar\"}}}");
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        cveSnapshotService.initialize(this.remoteConsumer);

        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        IndexRequest request = (IndexRequest) bulkCaptor.getValue().requests().getFirst();
        Assert.assertEquals(".wazuh-threatintel-vulnerabilities", request.index());
        Assert.assertEquals("TID-123", request.id());
    }

    /**
     * Builds an NDJSON snapshot of {@code count} kvdb documents, each padded to roughly {@code
     * approxBytesPerDoc} so the byte-based flush trigger can be exercised deterministically.
     */
    private String buildPaddedNdjson(int count, int approxBytesPerDoc) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            String filler = "x".repeat(Math.max(0, approxBytesPerDoc));
            sb.append("{\"name\": \"doc-")
                    .append(i)
                    .append("\", \"offset\": ")
                    .append(i + 1)
                    .append(", \"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"doc-")
                    .append(i)
                    .append("\", \"title\": \"")
                    .append(filler)
                    .append("\"}}}");
            if (i < count - 1) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * Re-initializes the {@link PluginSettings} singleton with the given {@code max_bulk_bytes} and
     * returns a fresh {@link SnapshotServiceImpl} bound to it (the service captures the singleton at
     * construction time). The caller is responsible for resetting the singleton when done.
     */
    private SnapshotServiceImpl serviceWithMaxBulkBytes(long maxBulkBytes) {
        PluginSettings.resetForTesting();
        Settings settings =
                Settings.builder()
                        .put("path.home", this.tempDir.toString())
                        .put("plugins.content_manager.max_bulk_bytes", maxBulkBytes)
                        .build();
        PluginSettings.getInstance(settings);

        Map<String, ContentIndex> indicesMap = new HashMap<>();
        indicesMap.put("kvdb", this.contentIndexMock);
        SnapshotServiceImpl service =
                new SnapshotServiceImpl(
                        "cti:catalog:consumer:ruleset", indicesMap, this.consumersIndex, this.environment);
        service.setSnapshotClient(this.snapshotClient);
        return service;
    }

    /**
     * The byte-size cap forces more flushes than the document-count cap alone. With a small {@code
     * max_bulk_bytes} and several large documents (all below {@code max_items_per_bulk}), {@code
     * executeBulk} must be invoked more than once.
     */
    public void testInitialize_ByteCapForcesAdditionalFlushes() throws Exception {
        // Cap at the 1 MB floor; 10 docs of ~512 KB each => several flushes, well under the 999-doc
        // count cap (the minimum allowed cap is 1 MB, so docs must be sized accordingly).
        long maxBulkBytes = 1L * 1024 * 1024;
        SnapshotServiceImpl service = serviceWithMaxBulkBytes(maxBulkBytes);
        try {
            String url = "http://example.com/bytecap.zip";
            when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);
            when(this.contentIndexMock.getWriteIndex()).thenReturn(".test-context-test-consumer-kvdb");

            Path zipPath =
                    this.createZipFileWithContent("data.json", this.buildPaddedNdjson(10, 512 * 1024));
            when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

            service.initialize(this.remoteConsumer);

            ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
            verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

            Assert.assertTrue(
                    "Byte cap should force more than one flush", bulkCaptor.getAllValues().size() > 1);
            int totalActions =
                    bulkCaptor.getAllValues().stream().mapToInt(BulkRequest::numberOfActions).sum();
            Assert.assertEquals("All 10 documents should be indexed", 10, totalActions);
        } finally {
            PluginSettings.resetForTesting();
        }
    }

    /**
     * Every flushed bulk request stays within the byte cap, except that a single document may push
     * the final accumulated request slightly over (the cap is checked after the doc is added). This
     * directly validates that per-request heap is bounded.
     */
    public void testInitialize_ByteCapBoundsPerBulkSize() throws Exception {
        long maxBulkBytes = 1L * 1024 * 1024;
        int docPadding = 512 * 1024;
        SnapshotServiceImpl service = serviceWithMaxBulkBytes(maxBulkBytes);
        try {
            String url = "http://example.com/bytecap2.zip";
            when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);
            when(this.contentIndexMock.getWriteIndex()).thenReturn(".test-context-test-consumer-kvdb");

            Path zipPath =
                    this.createZipFileWithContent("data.json", this.buildPaddedNdjson(12, docPadding));
            when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

            service.initialize(this.remoteConsumer);

            ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
            verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

            // The cap is checked AFTER each doc is added, so a single doc can push one bulk over the
            // cap. Allow one doc's worth of headroom; this proves no bulk grows unbounded.
            long upperBound = maxBulkBytes + docPadding + 512;
            for (BulkRequest request : bulkCaptor.getAllValues()) {
                Assert.assertTrue(
                        "Each bulk request must stay within the byte cap (+ one document of headroom): "
                                + request.estimatedSizeInBytes()
                                + " <= "
                                + upperBound,
                        request.estimatedSizeInBytes() <= upperBound);
            }
        } finally {
            PluginSettings.resetForTesting();
        }
    }

    /**
     * When document sizes stay far below {@code max_bulk_bytes}, the byte trigger never fires and the
     * count-based behavior is preserved: a handful of small docs produce a single flush.
     */
    public void testInitialize_CountPathUnaffectedWhenUnderByteCap() throws Exception {
        // Generous 16 MB cap; tiny docs => byte trigger never fires, single flush as before.
        long maxBulkBytes = 16L * 1024 * 1024;
        SnapshotServiceImpl service = serviceWithMaxBulkBytes(maxBulkBytes);
        try {
            String url = "http://example.com/smalldocs.zip";
            when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);
            when(this.contentIndexMock.getWriteIndex()).thenReturn(".test-context-test-consumer-kvdb");

            Path zipPath = this.createZipFileWithContent("data.json", this.buildPaddedNdjson(3, 8));
            when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

            service.initialize(this.remoteConsumer);

            ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
            verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

            Assert.assertEquals(
                    "Small docs under the byte cap should produce a single count-based flush",
                    1,
                    bulkCaptor.getAllValues().size());
            Assert.assertEquals(3, bulkCaptor.getValue().numberOfActions());
        } finally {
            PluginSettings.resetForTesting();
        }
    }

    public void testLazyCve_DocumentWrapperWithOffset() throws Exception {
        String line =
                "{\"resource\": \"CVE-2026-0001\", \"offset\": 5, \"payload\": {\"document\": "
                        + "{\"foo\": \"bar\", \"n\": 42, \"nested\": {\"a\": [1, 2, 3]}}}}";
        assertLazyMatchesBaseline(line);

        SnapshotServiceImpl.LazyCveDocument result = this.snapshotService.parseLazyCve(line);
        assertNotNull(result);
        assertEquals("CVE-2026-0001", result.id);
        assertTrue(result.hasOffset);
        assertEquals(5L, result.offset);
    }

    public void testLazyCve_ResourceFromNameField() throws Exception {
        String line =
                "{\"name\": \"TID-123\", \"offset\": 1, \"payload\": {\"document\": {\"foo\": \"bar\"}}}";
        assertLazyMatchesBaseline(line);
        assertEquals("TID-123", this.snapshotService.parseLazyCve(line).id);
    }

    public void testLazyCve_NoOffsetPresent() throws Exception {
        String line =
                "{\"resource\": \"CVE-2026-0002\", \"payload\": {\"document\": {\"foo\": \"bar\"}}}";
        assertLazyMatchesBaseline(line);
        assertFalse(
                "no offset field should not be persisted",
                this.snapshotService.parseLazyCve(line).hasOffset);
    }

    public void testLazyCve_DocumentContainingBracesAndQuotes() throws Exception {
        // Braces and quotes inside string values must not confuse the raw offset slicing.
        String line =
                "{\"resource\": \"CVE-2026-0003\", \"offset\": 9, \"payload\": {\"document\": "
                        + "{\"desc\": \"a } b { \\\"c\\\" }\", \"x\": 1}}}";
        assertLazyMatchesBaseline(line);
    }

    public void testLazyCve_PrettyPrintedLine() throws Exception {
        // Whitespace-formatted input: offsets and semantic equality must still hold.
        String line =
                "{\n  \"resource\": \"CVE-2026-0004\",\n  \"offset\": 7,\n  \"payload\": {\n"
                        + "    \"document\": {\n      \"foo\": \"bar\",\n      \"list\": [ 1, 2 ]\n    }\n  }\n}";
        assertLazyMatchesBaseline(line);
    }

    public void testLazyCve_ExtraEnvelopeFieldsIgnored() throws Exception {
        String line =
                "{\"resource\": \"CVE-2026-0005\", \"version\": 3, \"context\": \"vd\", \"offset\": 2, "
                        + "\"payload\": {\"document\": {\"foo\": \"bar\"}}}";
        assertLazyMatchesBaseline(line);
    }

    public void testLazyCve_FloatFidelityIsValueEqual() throws Exception {
        // 1.50 (lazy, verbatim) vs 1.5 (full-tree, reformatted) -> numerically equal.
        String line =
                "{\"resource\": \"CVE-2026-0006\", \"offset\": 4, \"payload\": {\"document\": "
                        + "{\"score\": 1.50}}}";
        assertLazyMatchesBaseline(line);
    }

    public void testLazyCve_PayloadIsDocumentNoWrapper() throws Exception {
        // Real CTI vulnerabilities shape: payload IS the CVE document (no "document" wrapper).
        String line =
                "{\"name\": \"CVE-1999-0001\", \"offset\": 1, \"payload\": {\"containers\": {\"cna\":"
                        + " {\"title\": \"t\"}}, \"cveMetadata\": {\"cveId\": \"CVE-1999-0001\"},"
                        + " \"dataType\": \"CVE_RECORD\", \"dataVersion\": \"5.1\"}}";
        assertLazyMatchesBaseline(line);
        SnapshotServiceImpl.LazyCveDocument result = this.snapshotService.parseLazyCve(line);
        assertEquals("CVE-1999-0001", result.id);
        assertEquals(1L, result.offset);
    }

    public void testLazyCve_GlobalResourceNoWrapper() throws Exception {
        String line =
                "{\"name\": \"FEED-GLOBAL\", \"offset\": 12, \"payload\": {\"vendors\": [\"a\", \"b\"]}}";
        assertLazyMatchesBaseline(line);
    }

    public void testLazyCve_FallbackOnUnknownResourcePattern() throws Exception {
        String line =
                "{\"resource\": \"NOT-A-CVE\", \"offset\": 1, \"payload\": {\"document\": {\"foo\": \"bar\"}}}";
        assertNull("unknown resource pattern must fall back", this.snapshotService.parseLazyCve(line));
    }

    public void testLazyCve_FallbackNoWrapperWithTypeKey() throws Exception {
        String line =
                "{\"resource\": \"CVE-2026-0007\", \"offset\": 1, \"payload\": {\"type\": \"x\","
                        + " \"foo\": \"bar\"}}";
        assertNull(
                "no-wrapper payload with a type key must fall back",
                this.snapshotService.parseLazyCve(line));
    }

    public void testLazyCve_FallbackWhenNoPayload() throws Exception {
        String line = "{\"resource\": \"CVE-2026-0008\", \"offset\": 1}";
        assertNull("missing payload must fall back", this.snapshotService.parseLazyCve(line));
    }

    public void testLazyCve_FallbackWhenNotAnObject() throws Exception {
        assertNull(this.snapshotService.parseLazyCve("[1, 2, 3]"));
    }

    /**
     * End-to-end: a CVE-only service must ingest a real-shape CVE line through the lazy fast path —
     * bypassing {@code processPayload} entirely — and index a correctly-shaped document.
     */
    public void testLazyCve_EndToEndBypassesProcessPayload() throws Exception {
        Map<String, ContentIndex> cveMap = new HashMap<>();
        cveMap.put("cves", this.contentIndexMock);
        SnapshotServiceImpl svc =
                new SnapshotServiceImpl(
                        "cti:catalog:consumer:vulnerabilities", cveMap, this.consumersIndex, this.environment);
        svc.setSnapshotClient(this.snapshotClient);
        when(this.contentIndexMock.getWriteIndex()).thenReturn(".wazuh-threatintel-vulnerabilities");

        String line =
                "{\"name\": \"CVE-2026-1234\", \"offset\": 7, \"payload\": {\"containers\": {\"cna\":"
                        + " {\"title\": \"t\"}}, \"dataType\": \"CVE_RECORD\"}}";
        Path zip = this.createZipFileWithContent("cve.json", line);

        svc.initialize(zip, null);

        // Fast path must bypass the resource-model transformation entirely.
        verify(this.contentIndexMock, never()).processPayload(any(JsonNode.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        IndexRequest request = (IndexRequest) bulkCaptor.getValue().requests().getFirst();
        assertEquals("CVE-2026-1234", request.id());
        JsonNode stored = this.cti.readTree(request.source().utf8ToString());
        assertEquals("CVE", stored.get("type").asText());
        assertEquals(7L, stored.get("offset").asLong());
        assertTrue("document must carry the raw CVE body", stored.get("document").has("containers"));
    }

    /**
     * The streaming envelope parse must extract the same {@code resource}/{@code name}, {@code
     * offset} and {@code payload} that the previous {@code readTree(line)} approach did — the payload
     * subtree is what every per-type transform consumes.
     */
    public void testParseEnvelope_MatchesReadTree() throws Exception {
        String line =
                "{\"name\": \"rule-1\", \"version\": 4, \"offset\": 42, \"payload\": {\"type\": \"rule\","
                        + " \"document\": {\"id\": \"R1\", \"related\": {\"sigma_id\": \"S-1\"}}}}";
        SnapshotServiceImpl.Envelope env = this.snapshotService.parseEnvelope(line);
        assertEquals("rule-1", env.resourceName);
        assertTrue(env.hasOffset);
        assertEquals(42L, env.offset);
        assertTrue(env.hasPayload);
        assertEquals(this.plain.readTree(line).get("payload"), env.payload);
    }

    public void testParseEnvelope_ResourceTakesPrecedenceOverName() throws Exception {
        String line =
                "{\"resource\": \"res-1\", \"name\": \"name-1\", \"payload\": {\"type\": \"kvdb\"}}";
        SnapshotServiceImpl.Envelope env = this.snapshotService.parseEnvelope(line);
        assertEquals("res-1", env.resourceName);
        assertFalse(env.hasOffset);
        assertTrue(env.hasPayload);
    }

    public void testParseEnvelope_NoPayload() throws Exception {
        SnapshotServiceImpl.Envelope env =
                this.snapshotService.parseEnvelope("{\"name\": \"x\", \"offset\": 1}");
        assertFalse("no payload field -> hasPayload false", env.hasPayload);
    }

    public void testParseEnvelope_NonObjectLineHasNoPayload() throws Exception {
        assertFalse(this.snapshotService.parseEnvelope("[1, 2, 3]").hasPayload);
    }

    /**
     * Reproduces the exact stored document the current pipeline would index for a CVE line: envelope
     * offset + type injection (as {@code processZipEntry} does), then {@link Cve#fromPayload}
     * serialized via the BigDecimal-enabled mapper (as {@code processPayload} does).
     */
    private String baselineStoredDocument(String line) throws Exception {
        JsonNode root = this.plain.readTree(line);
        JsonNode payload = root.get("payload");
        String resourceName =
                root.has("resource")
                        ? root.get("resource").asText()
                        : (root.has("name") ? root.get("name").asText() : null);
        String cveType = Cve.deriveType(resourceName);
        if (root.has("offset") && payload.isObject()) {
            ((ObjectNode) payload).put("offset", root.get("offset").asLong());
        }
        if (cveType != null && payload.isObject()) {
            ((ObjectNode) payload).put("type", cveType);
        }
        Cve cve = Cve.fromPayload(payload);
        return this.cti.valueToTree(cve).toString();
    }

    private void assertLazyMatchesBaseline(String line) throws Exception {
        SnapshotServiceImpl.LazyCveDocument result = this.snapshotService.parseLazyCve(line);
        assertNotNull("expected fast path to handle: " + line, result);
        JsonNode expected = this.cti.readTree(baselineStoredDocument(line));
        JsonNode actual = this.cti.readTree(result.toStoredDocument());
        assertTrue(
                "lazy output differs from baseline.\n  baseline=" + expected + "\n  lazy    =" + actual,
                semanticallyEqual(expected, actual));
    }

    /** Numeric-aware deep equality: numbers compare by value, everything else structurally. */
    private static boolean semanticallyEqual(JsonNode a, JsonNode b) {
        if (a.isNumber() && b.isNumber()) {
            return a.decimalValue().compareTo(b.decimalValue()) == 0;
        }
        if (a.isObject() && b.isObject()) {
            if (a.size() != b.size()) {
                return false;
            }
            Iterator<String> names = a.fieldNames();
            while (names.hasNext()) {
                String name = names.next();
                if (!b.has(name) || !semanticallyEqual(a.get(name), b.get(name))) {
                    return false;
                }
            }
            return true;
        }
        if (a.isArray() && b.isArray()) {
            if (a.size() != b.size()) {
                return false;
            }
            for (int i = 0; i < a.size(); i++) {
                if (!semanticallyEqual(a.get(i), b.get(i))) {
                    return false;
                }
            }
            return true;
        }
        return a.equals(b);
    }

    /** Helper to create a temporary ZIP file containing a single file with specific content. */
    private Path createZipFileWithContent(String fileName, String content) throws IOException {
        Path zipPath = this.tempDir.resolve("test_" + System.nanoTime() + ".zip");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zipPath))) {
            ZipEntry entry = new ZipEntry(fileName);
            zos.putNextEntry(entry);
            zos.write(content.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return zipPath;
    }

    /** Helper to create a temporary ZIP file containing multiple files with specific content. */
    private Path createZipFileWithEntries(Map<String, String> entries) throws IOException {
        Path zipPath = this.tempDir.resolve("test_multi_" + System.nanoTime() + ".zip");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zipPath))) {
            for (Map.Entry<String, String> entryData : entries.entrySet()) {
                ZipEntry entry = new ZipEntry(entryData.getKey());
                zos.putNextEntry(entry);
                zos.write(entryData.getValue().getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        }
        return zipPath;
    }

    /**
     * Tests that initializeFromLocal successfully processes a local zip file, does not invoke the
     * SnapshotClient, and deletes the source zip file after completion.
     */
    public void testInitializeFromPath_Success()
            throws IOException,
                    URISyntaxException,
                    ExecutionException,
                    InterruptedException,
                    TimeoutException {
        // Create a local ZIP file with snapshot content
        // spotless:off
        String jsonContent =
            "{\"name\": \"kvdb-001\", \"offset\": 50, \"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"kvdb-001\", \"title\": \"Test\"}}}\n"
            + "{\"name\": \"kvdb-002\", \"offset\": 75, \"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"kvdb-002\", \"title\": \"Test2\"}}}";
        // spotless:on
        Path localZip = this.createZipFileWithContent("data.json", jsonContent);
        Assert.assertTrue("Zip file should exist before init", Files.exists(localZip));

        // Pre-existing t0 consumer doc; SnapshotServiceImpl reads it to perform a partial update.
        String existingConsumerJson =
                "{\"name\":\"public-ruleset-5\",\"context\":\"t1-ruleset-5\","
                        + "\"type\":\"cti:catalog:consumer:ruleset\","
                        + "\"resource\":\"https://cti.example/catalog/contexts/t1-ruleset-5/consumers/public-ruleset-5\","
                        + "\"is_public\":true,\"status\":\"running\",\"local_offset\":0,\"remote_offset\":75}";
        org.opensearch.action.get.GetResponse t0Response =
                mock(org.opensearch.action.get.GetResponse.class);
        when(t0Response.isExists()).thenReturn(true);
        when(t0Response.getSourceAsString()).thenReturn(existingConsumerJson);
        when(this.consumersIndex.getConsumer("cti:catalog:consumer:ruleset")).thenReturn(t0Response);

        // Act
        boolean result = this.snapshotService.initialize(localZip, null);

        // Assert
        Assert.assertTrue("initialize should return true", result);

        // SnapshotClient should NOT be invoked for local init
        verify(this.snapshotClient, never()).downloadFile(anyString());

        // Indices should be cleared
        verify(this.contentIndexMock, atLeastOnce()).clear();

        // Documents should be processed and indexed
        verify(this.contentIndexMock, atLeastOnce()).processPayload(any(JsonNode.class));
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(any(BulkRequest.class));
        verify(this.contentIndexMock).waitForPendingUpdates();

        // Consumer state should be updated with maxOffsetSeen on local_offset; identity and
        // remote_offset are preserved from the t0 doc.
        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());
        LocalConsumer persisted = consumerCaptor.getValue();
        Assert.assertEquals(75L, persisted.getLocalOffset());
        Assert.assertEquals(75L, persisted.getRemoteOffset());
        Assert.assertEquals("public-ruleset-5", persisted.getName());

        // Source zip should be deleted
        Assert.assertFalse("Source zip should be deleted after init", Files.exists(localZip));
    }

    /**
     * Tests that maxOffsetSeen correctly tracks the maximum offset across all entries in the
     * snapshot.
     */
    public void testInitializeFromPath_MaxOffsetTracking() throws IOException {
        // spotless:off
        String jsonContent =
            "{\"name\": \"r1\", \"offset\": 10, \"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"r1\"}}}\n"
            + "{\"name\": \"r2\", \"offset\": 200, \"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"r2\"}}}\n"
            + "{\"name\": \"r3\", \"offset\": 150, \"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"r3\"}}}";
        // spotless:on
        Path localZip = this.createZipFileWithContent("data.json", jsonContent);

        this.snapshotService.initialize(localZip, null);

        Assert.assertEquals(
                "maxOffsetSeen should be the highest offset in the file",
                200L,
                this.snapshotService.getMaxOffsetSeen());
    }

    /**
     * Local-path initialization preserves all identity fields from the existing (t0-written) consumer
     * document and only mutates {@code local_offset}. Identity, {@code is_public}, {@code status} and
     * {@code remote_offset} are owned by the t0 write in {@code AbstractConsumerService}, not by
     * {@code SnapshotServiceImpl}.
     */
    public void testInitializeFromPath_PreservesT0FieldsAndOnlyUpdatesLocalOffset() throws Exception {
        // spotless:off
        String dataJson =
            """
                {"name":"kvdb-1","offset":42,"payload":{"type":"kvdb","document":{"id":"kvdb-1"}}}
                """;
        // spotless:on

        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("data.json", dataJson);
        Path localZip = this.createZipFileWithEntries(entries);

        String existingConsumerJson =
                "{\"name\":\"public-ruleset-5\",\"context\":\"t1-ruleset-5\","
                        + "\"type\":\"cti:catalog:consumer:ruleset\","
                        + "\"resource\":\"https://example/catalog/contexts/t1-ruleset-5/consumers/public-ruleset-5\","
                        + "\"is_public\":true,\"status\":\"running\",\"local_offset\":0,\"remote_offset\":42}";

        org.opensearch.action.get.GetResponse existingGetResponse =
                mock(org.opensearch.action.get.GetResponse.class);
        when(existingGetResponse.isExists()).thenReturn(true);
        when(existingGetResponse.getSourceAsString()).thenReturn(existingConsumerJson);
        when(this.consumersIndex.getConsumer("cti:catalog:consumer:ruleset"))
                .thenReturn(existingGetResponse);

        boolean initialized = this.snapshotService.initialize(localZip, null);
        Assert.assertTrue(initialized);

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex, atLeastOnce()).setConsumer(consumerCaptor.capture());

        LocalConsumer persisted = consumerCaptor.getValue();
        Assert.assertEquals("public-ruleset-5", persisted.getName());
        Assert.assertEquals("t1-ruleset-5", persisted.getContext());
        Assert.assertEquals("cti:catalog:consumer:ruleset", persisted.getType());
        Assert.assertEquals(
                "https://example/catalog/contexts/t1-ruleset-5/consumers/public-ruleset-5",
                persisted.getResource());
        Assert.assertTrue(persisted.isPublic());
        Assert.assertEquals(LocalConsumer.Status.RUNNING, persisted.getStatus());
        Assert.assertEquals(42L, persisted.getLocalOffset());
        Assert.assertEquals(42L, persisted.getRemoteOffset());
    }

    /**
     * When no t0 document exists, the partial local_offset update is skipped (returning false). The
     * snapshot data is still indexed, but no consumer document is written by {@code
     * SnapshotServiceImpl}.
     */
    public void testInitializeFromPath_SkipsConsumerUpdateWhenNoT0Doc() throws Exception {
        String dataJson =
                "{\"name\":\"kvdb-1\",\"offset\":42,\"payload\":{\"type\":\"kvdb\",\"document\":{\"id\":\"kvdb-1\"}}}";
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("data.json", dataJson);
        Path localZip = this.createZipFileWithEntries(entries);

        org.opensearch.action.get.GetResponse absent =
                mock(org.opensearch.action.get.GetResponse.class);
        when(absent.isExists()).thenReturn(false);
        when(this.consumersIndex.getConsumer("cti:catalog:consumer:ruleset")).thenReturn(absent);

        boolean initialized = this.snapshotService.initialize(localZip, null);
        Assert.assertFalse(initialized);
        verify(this.consumersIndex, never()).setConsumer(any(LocalConsumer.class));
    }

    /**
     * Tests that initializeFromLocal returns false when the zip file does not exist or is corrupted.
     */
    public void testInitializeFromPath_NonExistentFile() throws IOException, URISyntaxException {
        Path nonExistentPath = this.tempDir.resolve("does_not_exist.zip");

        boolean result = this.snapshotService.initialize(nonExistentPath, null);

        Assert.assertFalse("initialize should return false for missing file", result);
        verify(this.snapshotClient, never()).downloadFile(anyString());
    }
}
