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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.contentmanager.cti.catalog.client.SnapshotClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.service.ClusterService;
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
    @Mock private ClusterService clusterService;
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

        PluginSettings.getInstance(settings, this.clusterService);
        List<ContentIndex> contentIndices = Collections.singletonList(this.contentIndexMock);
        String context = "test-context";
        String consumer = "test-consumer";
        this.snapshotService = new SnapshotServiceImpl(context, consumer, contentIndices, consumersIndex, environment);
        this.snapshotService.setSnapshotClient(this.snapshotClient);
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
        when(remoteConsumer.getSnapshotLink()).thenReturn("");

        this.snapshotService.initialize(remoteConsumer);

        verify(snapshotClient, never()).downloadFile(anyString());
        verify(contentIndexMock, never()).clear();
    }

    /**
     * Tests that the initialization aborts if the download fails (returns null).
     */
    public void testInitialize_DownloadFails() throws IOException, URISyntaxException {
        String url = "http://example.com/snapshot.zip";
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);
        when(snapshotClient.downloadFile(url)).thenReturn(null);

        this.snapshotService.initialize(remoteConsumer);

        verify(snapshotClient).downloadFile(url);
        verify(contentIndexMock, never()).clear();
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
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);
        when(remoteConsumer.getOffset()).thenReturn(offset);
        Path zipPath = createZipFileWithContent("data.json",
            "{\"payload\": {\"type\": \"kvdb\", \"document\": {\"id\": \"12345678\", \"title\": \"Test Kvdb\"}}}"
        );
        when(snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(remoteConsumer);

        // Assert
        verify(contentIndexMock).clear();
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        BulkRequest request = bulkCaptor.getValue();
        assertEquals(1, request.numberOfActions());
        IndexRequest indexRequest = (IndexRequest) request.requests().getFirst();

        assertEquals(".test-context-test-consumer-kvdb", indexRequest.index());
        assertEquals("12345678", indexRequest.id());

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(consumersIndex).setConsumer(consumerCaptor.capture());
        assertEquals(offset, consumerCaptor.getValue().getLocalOffset());
    }

    /**
     * Tests that documents with type "policy" are skipped.
     */
    public void testInitialize_SkipPolicyType() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/policy.zip";
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);

        Path zipPath = createZipFileWithContent("policy.json",
            "{\"payload\": {\"type\": \"policy\", \"document\": {\"id\": \"p1\"}}}"
        );
        when(snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(remoteConsumer);

        // Assert
        verify(contentIndexMock, never()).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests that type "decoder" documents are enriched with a YAML field.
     */
    public void testInitialize_EnrichDecoderWithYaml() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/decoder.zip";
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{\"payload\": {\"type\": \"decoder\", \"document\": {\"name\": \"syslog\", \"parent\": \"root\"}}}";
        Path zipPath = createZipFileWithContent("decoder.json", jsonContent);
        when(snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(remoteConsumer);

        // Assert
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(contentIndexMock).executeBulk(bulkCaptor.capture());

        IndexRequest request = (IndexRequest) bulkCaptor.getValue().requests().getFirst();
        String source = request.source().utf8ToString();

        assertTrue("Should contain 'decoder' field", source.contains("\"decoder\":"));
    }

    /**
     * Tests preprocessing: 'related.sigma_id' should be renamed to 'related.id'.
     */
    public void testInitialize_PreprocessSigmaId() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/sigma.zip";
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{\"payload\": {\"type\": \"rule\", \"document\": {\"id\": \"R1\", \"related\": {\"sigma_id\": \"S-123\", \"type\": \"test-value\"}}}}";
        Path zipPath = createZipFileWithContent("sigma.json", jsonContent);
        when(snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(remoteConsumer);

        // Assert
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(contentIndexMock).executeBulk(bulkCaptor.capture());

        IndexRequest request = (IndexRequest) bulkCaptor.getValue().requests().get(0);
        String source = request.source().utf8ToString();

        assertFalse("Should not contain sigma_id", source.contains("\"sigma_id\""));
        assertTrue("Should contain id with value S-123", source.contains("\"id\":\"S-123\""));
    }

    /**
     * Tests that files without 'payload', 'type', or 'document' are skipped.
     */
    public void testInitialize_InvalidJsonStructure() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/invalid.zip";
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent =
                "{}\n" + // Missing payload
                "{\"payload\": {}}\n" + // Missing type
                "{\"payload\": {\"type\": \"valid\", \"no_doc\": {}}}"; // Missing document

        Path zipPath = createZipFileWithContent("invalid.json", jsonContent);
        when(snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(remoteConsumer);

        // Assert
        verify(contentIndexMock, never()).executeBulk(any(BulkRequest.class));
    }

    /**
     * Tests preprocessing with related array, objects inside array should also be sanitized.
     */
    public void testInitialize_PreprocessSigmaIdInArray() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/sigma_array.zip";
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{\"payload\": {\"type\": \"rule\", \"document\": {\"id\": \"R2\", \"related\": [{\"sigma_id\": \"999\"}]}}}";
        Path zipPath = createZipFileWithContent("sigma_array.json", jsonContent);
        when(snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(remoteConsumer);

        // Assert
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(contentIndexMock).executeBulk(bulkCaptor.capture());

        String source = ((IndexRequest) bulkCaptor.getValue().requests().getFirst()).source().utf8ToString();

        assertFalse("Should not contain sigma_id", source.contains("\"sigma_id\""));
        assertTrue("Should contain id with value 999", source.contains("999"));
    }

    /**
     * Tests that if a file contains a mix of valid JSON and corrupt lines (parsing errors),
     * the service logs the error, skips the bad line, and continues indexing the valid ones.
     */
    public void testInitialize_SkipInvalidJson() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/corrupt.zip";
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent =
            "{\"payload\": {\"type\": \"reputation\", \"document\": {\"id\": \"1\", \"ip\": \"1.1.1.1\"}}}\n" +
                "THIS_IS_NOT_JSON_{{}}\n" +
                "{\"payload\": {\"type\": \"reputation\", \"document\": {\"id\": \"2\", \"ip\": \"2.2.2.2\"}}}";

        Path zipPath = createZipFileWithContent("mixed.json", jsonContent);
        when(snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(remoteConsumer);

        // Assert
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(contentIndexMock, atLeastOnce()).executeBulk(bulkCaptor.capture());

        // We expect exactly 2 valid actions (Line 1 and Line 3), skipping Line 2
        int totalActions = bulkCaptor.getAllValues().stream()
            .mapToInt(BulkRequest::numberOfActions)
            .sum();

        assertEquals("Should index the 2 valid documents and skip the corrupt one", 2, totalActions);
    }

    /**
     * Tests that the generated YAML for decoders strictly respects the order defined in DECODER_ORDER_KEYS.
     */
    public void testInitialize_DecoderYamlKeyOrdering() throws IOException, URISyntaxException {
        // Mock
        String url = "http://example.com/decoder_order.zip";
        when(remoteConsumer.getSnapshotLink()).thenReturn(url);

        String jsonContent = "{\"payload\": {\"type\": \"decoder\", \"document\": " +
            "{\"check\": \"some_regex\", \"name\": \"ssh-decoder\", \"parents\": [\"root\"]}}}";

        Path zipPath = createZipFileWithContent("decoder_order.json", jsonContent);
        when(snapshotClient.downloadFile(url)).thenReturn(zipPath);

        // Act
        this.snapshotService.initialize(remoteConsumer);

        // Assert
        ArgumentCaptor<BulkRequest> bulkCaptor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(contentIndexMock).executeBulk(bulkCaptor.capture());

        IndexRequest request = (IndexRequest) bulkCaptor.getValue().requests().getFirst();
        String source = request.source().utf8ToString();
        String yamlContent = new ObjectMapper().readTree(source).path("decoder").asText();

        assertTrue("YAML content should contain 'name'", yamlContent.contains("name"));
        assertTrue("Field 'name' should appear before 'parents'",
            yamlContent.indexOf("name") < yamlContent.indexOf("parents"));
        assertTrue("Field 'parents' should appear before 'check'",
            yamlContent.indexOf("parents") < yamlContent.indexOf("check"));
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
