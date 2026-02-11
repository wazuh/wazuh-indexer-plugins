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

import com.google.gson.JsonObject;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.wazuh.contentmanager.cti.catalog.client.SnapshotClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
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

        String context = "test-context";
        String consumer = "test-consumer";

        this.snapshotService =
                new SnapshotServiceImpl(
                        context, consumer, indicesMap, this.consumersIndex, this.environment);
        this.snapshotService.setSnapshotClient(this.snapshotClient);

        when(this.contentIndexMock.processPayload(any(JsonObject.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(this.contentIndexMock.getIndexName()).thenReturn(".test-context-test-consumer-kvdb");
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
     * Tests a successful initialization flow: 1. Download succeeds. 2. Unzip succeeds. 3. Files are
     * parsed and indexed. 4. Consumer index is updated (check using the local consumer)
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

        Path zipPath =
                this.createZipFileWithContent(
                        "data.json",
                        "{\"name\": \"12345678\", \"offset\": 1, \"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"12345678\", \"title\": \"Test Kvdb\"}}}");
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock, times(5)).clear();
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        BulkRequest request = bulkCaptor.getValue();
        assertEquals(1, request.numberOfActions());
        IndexRequest indexRequest = (IndexRequest) request.requests().getFirst();

        assertEquals(".test-context-test-consumer-kvdb", indexRequest.index());
        assertEquals("12345678", indexRequest.id());

        // Verify waiting for pending updates
        verify(this.contentIndexMock).waitForPendingUpdates();

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());
        assertEquals(offset, consumerCaptor.getValue().getLocalOffset());
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
        when(this.contentIndexMock.getIndexName()).thenReturn(".test-context-test-consumer-policy");

        Path zipPath =
                this.createZipFileWithContent(
                        "policy.json",
                        "{\"name\": \"123\", \"offset\": 1, \"payload\": {\"type\": \"policy\", \"document\": {\"id\": \"123\"}}}");
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock).executeBulk(bulkCaptor.capture());

        IndexRequest request = (IndexRequest) bulkCaptor.getValue().requests().getFirst();

        assertEquals(".test-context-test-consumer-policy", request.index());
        assertEquals("123", request.id());
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
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
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
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
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
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
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
        verify(this.contentIndexMock, atLeastOnce()).processPayload(any(JsonObject.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        // We expect exactly 2 valid actions (Line 1 and Line 3), skipping Line 2
        int totalActions =
                bulkCaptor.getAllValues().stream().mapToInt(BulkRequest::numberOfActions).sum();

        assertEquals("Should index the 2 valid documents and skip the corrupt one", 2, totalActions);
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
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
        verify(this.contentIndexMock).executeBulk(any(BulkRequest.class));
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
}
