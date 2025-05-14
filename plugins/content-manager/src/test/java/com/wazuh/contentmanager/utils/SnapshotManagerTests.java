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
package com.wazuh.contentmanager.utils;

import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.Iterator;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.cti.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

/** Class to handle unzip tests */
public class SnapshotManagerTests extends OpenSearchTestCase {
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private CommandManagerClient commandClient;
    private CTIClient ctiClient;
    private Privileged privilegedSpy;
    private ConsumerInfo consumerInfo;
    private SnapshotManager snapshotManager;

    @Mock private Environment mockEnvironment;
    @Mock private ClusterService mockClusterService;
    @InjectMocks private PluginSettings pluginSettings;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        Path envDir = createTempDir();
        Settings settings =
                Settings.builder()
                        .put("path.home", envDir.toString()) // Required by OpenSearch
                        .putList("path.repo", envDir.toString())
                        .put("content_manager.max_changes", 1000)
                        .build();
        this.mockEnvironment = spy(new Environment(settings, envDir));
        when(this.mockEnvironment.settings()).thenReturn(settings);
        this.pluginSettings =
                PluginSettings.getInstance(this.mockEnvironment.settings(), this.mockClusterService);

        this.ctiClient = mock(CTIClient.class);
        this.commandClient = mock(CommandManagerClient.class);
        this.contextIndex = mock(ContextIndex.class);
        this.contentIndex = mock(ContentIndex.class);
        this.privilegedSpy = Mockito.spy(Privileged.class);
        this.snapshotManager =
                Mockito.spy(
                        new SnapshotManager(
                                this.ctiClient,
                                this.commandClient,
                                this.mockEnvironment,
                                this.contextIndex,
                                this.contentIndex,
                                this.privilegedSpy,
                                this.pluginSettings));

        this.consumerInfo = mock(ConsumerInfo.class);
    }

    /**
     * Test that updating the context index works
     *
     * @throws IOException Rethrown from updateContextIndex()
     */
    public void testSuccessfulConsumerIndexing() throws IOException {
        // Fixtures
        ConsumerInfo consumerInfo =
                new ConsumerInfo("test-name", "test-context", 1L, 1L, "http://example.com");
        IndexResponse response = mock(IndexResponse.class, "SuccessfulResponse");

        // Mocks
        doReturn(consumerInfo).when(this.ctiClient).getConsumerInfo();
        doReturn(this.consumerInfo).when(this.contextIndex).get(anyString(), anyString());
        doReturn(true).when(this.contextIndex).index(consumerInfo);
        doReturn(DocWriteResponse.Result.CREATED).when(response).getResult();

        // Act &6 Assert
        this.snapshotManager.initConsumer();
        verify(this.contextIndex).index(any(ConsumerInfo.class));
    }

    /**
     * Ensure IOException is thrown when updateContextIndex() fails
     *
     * @throws IOException error parsing CTI response.
     */
    public void testFailedConsumerIndexing() throws IOException {
        // Fixtures
        ConsumerInfo consumerInfo =
                new ConsumerInfo("test-name", "test-context", 1L, 1L, "http://example.com");
        IndexResponse response = mock(IndexResponse.class, "FailedResponse");

        // Mocks
        doReturn(consumerInfo).when(this.ctiClient).getConsumerInfo();
        doReturn(this.consumerInfo).when(this.contextIndex).get(anyString(), anyString());
        doReturn(false).when(this.contextIndex).index(consumerInfo);
        doReturn(DocWriteResponse.Result.NOT_FOUND).when(response).getResult();

        // Act && Assert
        assertThrows(IOException.class, () -> this.snapshotManager.initConsumer());
    }

    /**
     * Check that the fromSnapshot() method is being executed
     *
     * @throws IOException rethrown from unzip()
     */
    public void testSuccessfulIndexSnapshot() throws IOException {
        doReturn(this.consumerInfo).when(this.contextIndex).get(anyString(), anyString());
        Path snapshotZip = mock(Path.class);
        doReturn("http://example.com/file.zip").when(this.consumerInfo).getLastSnapshotLink();
        doReturn(snapshotZip).when(this.ctiClient).download(anyString(), any(Environment.class));
        Path outputDir = mock(Path.class);
        doReturn(outputDir).when(this.mockEnvironment).tmpFile();
        DirectoryStream<Path> stream = mock(DirectoryStream.class);
        Path jsonPath = mock(Path.class);
        Iterator<Path> iterator = mock(Iterator.class);
        doReturn(iterator).when(stream).iterator();
        doReturn(jsonPath).when(iterator).next();
        doReturn(stream).when(this.snapshotManager).getStream(any(Path.class));
        doNothing().when(this.snapshotManager).unzip(any(Path.class), any(Path.class));
        this.snapshotManager.indexSnapshot(this.consumerInfo);
        verify(this.contentIndex).fromSnapshot(anyString());
    }
}
