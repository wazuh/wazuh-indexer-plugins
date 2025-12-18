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
package com.wazuh.contentmanager.cti.catalog.service;

import com.google.gson.JsonObject;
import com.wazuh.contentmanager.cti.catalog.client.SnapshotClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

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
        Settings settings = Settings.builder()
            .put("path.home", this.tempDir.toString())
            .build();
        when(this.environment.tmpDir()).thenReturn(this.tempDir);
        when(this.environment.settings()).thenReturn(settings);

        PluginSettings.getInstance(settings);
        List<ContentIndex> contentIndices = Collections.singletonList(this.contentIndexMock);
        String context = "test-context";
        String consumer = "test-consumer";
        this.snapshotService = new SnapshotServiceImpl(context, consumer, contentIndices, this.consumersIndex, this.environment);
        this.snapshotService.setSnapshotClient(this.snapshotClient);

        when(this.contentIndexMock.processPayload(any(JsonObject.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));
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
     */
    public void testInitialize_EmptyUrl() throws IOException, URISyntaxException {
        when(this.remoteConsumer.getSnapshotLink()).thenReturn("");

        this.snapshotService.initialize(this.remoteConsumer);

        verify(this.snapshotClient, never()).downloadFile(anyString());
        verify(this.contentIndexMock, never()).clear();
    }

    /**
     * Tests that the initialization aborts if the download fails (returns null).
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
     * Tests a successful initialization flow:
     * 1. Download succeeds.
     * 2. Unzip succeeds.
     * 3. Files are parsed and indexed.
     * 4. Consumer index is updated (check using the local consumer)
     */
    public void testInitialize_Success() throws IOException, ExecutionException, InterruptedException, TimeoutException, URISyntaxException {
        // Mock
        String url = "http://example.com/snapshot.zip";
        long offset = 100L;
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);
        when(this.remoteConsumer.getOffset()).thenReturn(offset);
        when(this.remoteConsumer.getSnapshotOffset()).thenReturn(offset);

        Path zipPath = createZipFileWithContent("data.json",
            "{\"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"12345678\", \"title\": \"Test Kvdb\"}}}"
        );
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).clear();
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        BulkRequest request = bulkCaptor.getValue();
        assertEquals(1, request.numberOfActions());
        IndexRequest indexRequest = (IndexRequest) request.requests().getFirst();

        assertEquals(".test-context-test-consumer-kvdb", indexRequest.index());
        assertEquals("12345678", indexRequest.id());

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());
        assertEquals(offset, consumerCaptor.getValue().getLocalOffset());
    }

    /**
     * Tests that documents with type "policy" are indexed correctly.
     */
    public void testInitialize_IndexesPolicyType() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/policy.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        Path zipPath = createZipFileWithContent("policy.json",
            "{\"payload\": {\"type\": \"policy\", \"document\": {\"id\": \"p1\"}}}"
        );
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock).executeBulk(bulkCaptor.capture());

        IndexRequest request = (IndexRequest) bulkCaptor.getValue().requests().getFirst();

        assertEquals(".test-context-test-consumer-policy", request.index());
        assertEquals("p1", request.id());
    }

    /**
     * Tests that type "decoder" documents are delegated to ContentIndex for processing.
     */
    public void testInitialize_EnrichDecoderWithYaml() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/decoder.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{\"payload\": {\"type\": \"decoder\", \"document\": {\"name\": \"syslog\", \"parent\": \"root\"}}}";
        Path zipPath = createZipFileWithContent("decoder.json", jsonContent);
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
     */
    public void testInitialize_PreprocessSigmaId() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/sigma.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{\"payload\": {\"type\": \"rule\", \"document\": {\"id\": \"R1\", \"related\": {\"sigma_id\": \"S-123\", \"type\": \"test-value\"}}}}";
        Path zipPath = createZipFileWithContent("sigma.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
        verify(this.contentIndexMock).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests that files without 'payload', 'type', or 'document' are skipped.
     */
    public void testInitialize_InvalidJsonStructure() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/invalid.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent =
            "{}\n" +
                "{\"payload\": {}}";

        Path zipPath = createZipFileWithContent("invalid.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock, never()).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests preprocessing with related array: Verifies that payload processing is delegated.
     */
    public void testInitialize_PreprocessSigmaIdInArray() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/sigma_array.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{\"payload\": {\"type\": \"rule\", \"document\": {\"id\": \"R2\", \"related\": [{\"sigma_id\": \"999\"}]}}}";
        Path zipPath = createZipFileWithContent("sigma_array.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
        verify(this.contentIndexMock).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests that if a file contains a mix of valid JSON and corrupt lines (parsing errors),
     * the service logs the error, skips the bad line, and continues indexing the valid ones.
     */
    public void testInitialize_SkipInvalidJson() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/corrupt.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent =
            "{\"payload\": {\"type\": \"reputation\", \"document\": {\"id\": \"1\", \"ip\": \"1.1.1.1\"}}}\n" +
                "THIS_IS_NOT_JSON_{{}}\n" +
                "{\"payload\": {\"type\": \"reputation\", \"document\": {\"id\": \"2\", \"ip\": \"2.2.2.2\"}}}";

        Path zipPath = createZipFileWithContent("mixed.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock, atLeastOnce()).processPayload(any(JsonObject.class));
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(this.contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        // We expect exactly 2 valid actions (Line 1 and Line 3), skipping Line 2
        int totalActions = bulkCaptor.getAllValues().stream()
            .mapToInt(BulkRequest::numberOfActions)
            .sum();

        assertEquals("Should index the 2 valid documents and skip the corrupt one", 2, totalActions);
    }

    /**
     * Tests delegation for decoder YAML processing.
     */
    public void testInitialize_DecoderYamlDelegation() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/decoder_order.zip";
        when(this.remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{\"payload\": {\"type\": \"decoder\", \"document\": " +
            "{\"check\": \"some_regex\", \"name\": \"ssh-decoder\", \"parents\": [\"root\"]}}}";

        Path zipPath = createZipFileWithContent("decoder_order.json", jsonContent);
        when(this.snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(this.remoteConsumer);

        // Assert
        verify(this.contentIndexMock).processPayload(any(JsonObject.class));
        verify(this.contentIndexMock).executeBulk(any(BulkRequest.class));
    }

    /**
     * Helper to create a temporary ZIP file containing a single file with specific content.
     */
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
