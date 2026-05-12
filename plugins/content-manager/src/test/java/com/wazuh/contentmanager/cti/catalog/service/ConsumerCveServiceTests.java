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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.CreatePitAction;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.search.DeletePitAction;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.search.DocValueFormat;
import org.opensearch.search.SearchHit;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ConsumerCveService}. Verifies global hash computation and storage using
 * mocked PIT and search operations.
 */
public class ConsumerCveServiceTests extends OpenSearchTestCase {

    private static class TestableConsumerCveService extends ConsumerCveService {
        TestableConsumerCveService(
                Client client, ConsumersIndex consumersIndex, Environment environment) {
            super(client, consumersIndex, environment);
        }

        @Override
        public void onSyncComplete(boolean isUpdated) {
            // No-op for fallback-path unit testing.
        }
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ConsumerCveService service;
    private AutoCloseable closeable;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private Client client;

    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;
    @Mock private ConsumerService consumerService;
    @Mock private SnapshotServiceImpl snapshotService;
    @Mock private org.opensearch.action.get.GetResponse getResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        ConsumerCveServiceTests.clearPluginSettings();
        PluginSettings.getInstance(Settings.EMPTY);
        this.service = new ConsumerCveService(this.client, this.consumersIndex, this.environment);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        ConsumerCveServiceTests.clearPluginSettings();
        super.tearDown();
    }

    private static void clearPluginSettings() {
        PluginSettings.resetForTesting();
    }

    /**
     * Creates a SearchHit with the given id and SHA-256 hash. Sort values are set to [id] for the
     * paginated iteration.
     */
    private SearchHit createCveHit(int docId, String id, String sha256) {
        String source = "{\"hash\":{\"sha256\":\"" + sha256 + "\"}}";
        SearchHit hit = new SearchHit(docId, id, Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(new org.opensearch.core.common.bytes.BytesArray(source));
        hit.sortValues(new Object[] {id}, new DocValueFormat[] {DocValueFormat.RAW});
        return hit;
    }

    /** Mocks PIT creation and deletion for the test client. */
    @SuppressWarnings("unchecked")
    private void mockPitLifecycle() {
        CreatePitResponse pitResponse = mock(CreatePitResponse.class);
        when(pitResponse.getId()).thenReturn("test-pit-id");
        ActionFuture<CreatePitResponse> pitFuture = mock(ActionFuture.class);
        when(pitFuture.actionGet()).thenReturn(pitResponse);
        when(this.client.execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class)))
                .thenReturn(pitFuture);

        ActionFuture<?> deletePitFuture = mock(ActionFuture.class);
        when(this.client.execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class)))
                .thenReturn((ActionFuture) deletePitFuture);
    }

    /** Mocks the index response for storing the hash document. */
    @SuppressWarnings("unchecked")
    private void mockIndexResponse() {
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenReturn(mock(IndexResponse.class));
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
    }

    /** Tests that onSyncComplete does nothing when isUpdated is false. */
    public void testOnSyncCompleteSkipsWhenNotUpdated() {
        this.service.onSyncComplete(false);

        verify(this.client, never()).execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
    }

    /** Tests that getMappings returns the CVE mappings. */
    public void testGetMappingsReturnsExpectedMappings() {
        Map<String, String> mappings = this.service.getMappings();

        assertNotNull(mappings);
        assertEquals(1, mappings.size());
        assertEquals(Constants.KEY_CVES, mappings.get(Constants.KEY_CVES));
    }

    /**
     * Tests fallback to the local snapshot when a custom catalog URL is configured but remote
     * retrieval fails.
     */
    public void testSynchronizeFallsBackToLocalSnapshotWhenRemoteConsumerIsUnavailable()
            throws Exception {
        Path pluginsDir = LuceneTestCase.createTempDir();
        Path localSnapshot =
                pluginsDir
                        .resolve(Constants.PLUGIN_DIR_NAME)
                        .resolve(Constants.CTI_SNAPSHOTS_DIR)
                        .resolve(Constants.CVE_SNAPSHOT_FILENAME);
        Files.createDirectories(localSnapshot.getParent());
        Files.writeString(localSnapshot, "placeholder");

        ConsumerCveServiceTests.clearPluginSettings();
        PluginSettings.getInstance(
                Settings.builder()
                        .put(
                                "plugins.content_manager.catalog.vulnerabilities",
                                "https://cti.example/api/v1/catalog/contexts/t1-vulnerabilities-5/consumers/public-vulnerabilities-5")
                        .build());

        when(this.environment.pluginsDir()).thenReturn(pluginsDir);
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);
        when(this.consumerService.getLocalConsumer()).thenReturn(null);
        when(this.consumerService.getRemoteConsumer()).thenReturn(null);
        when(this.consumersIndex.getConsumer("cti:catalog:consumer:vulnerabilities"))
                .thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(false);
        when(this.snapshotService.initialize(eq(localSnapshot), any())).thenReturn(true);
        when(this.snapshotService.getMaxOffsetSeen()).thenReturn(222L);

        TestableConsumerCveService fallbackService =
                new TestableConsumerCveService(this.client, this.consumersIndex, this.environment);
        fallbackService.setConsumerService(this.consumerService);
        fallbackService.setSnapshotService(this.snapshotService);

        fallbackService.synchronize();

        verify(this.snapshotService).initialize(eq(localSnapshot), any());
        verify(this.snapshotService, never())
                .initialize(any(com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer.class));
    }

    /** Tests fallback to the local snapshot when remote snapshot initialization fails. */
    public void testSynchronizeFallsBackToLocalSnapshotWhenRemoteSnapshotInitializationFails()
            throws Exception {
        Path pluginsDir = LuceneTestCase.createTempDir();
        Path localSnapshot =
                pluginsDir
                        .resolve(Constants.PLUGIN_DIR_NAME)
                        .resolve(Constants.CTI_SNAPSHOTS_DIR)
                        .resolve(Constants.CVE_SNAPSHOT_FILENAME);
        Files.createDirectories(localSnapshot.getParent());
        Files.writeString(localSnapshot, "placeholder");

        ConsumerCveServiceTests.clearPluginSettings();
        PluginSettings.getInstance(
                Settings.builder()
                        .put(
                                "plugins.content_manager.catalog.vulnerabilities",
                                "https://cti.example/api/v1/catalog/contexts/t1-vulnerabilities-5/consumers/public-vulnerabilities-5")
                        .build());

        RemoteConsumer remoteConsumer = mock(RemoteConsumer.class);

        when(this.environment.pluginsDir()).thenReturn(pluginsDir);
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);
        when(this.consumerService.getLocalConsumer()).thenReturn(null);
        when(this.consumerService.getRemoteConsumer()).thenReturn(remoteConsumer);
        when(remoteConsumer.getSnapshotLink())
                .thenReturn("https://cti.example/store/vulnerabilities.zip");
        when(remoteConsumer.getSnapshotOffset()).thenReturn(222L);
        when(remoteConsumer.getOffset()).thenReturn(222L);
        when(this.consumersIndex.getConsumer("cti:catalog:consumer:vulnerabilities"))
                .thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(false);
        when(this.snapshotService.initialize(eq(remoteConsumer))).thenReturn(false);
        when(this.snapshotService.initialize(eq(localSnapshot), any())).thenReturn(true);
        when(this.snapshotService.getMaxOffsetSeen()).thenReturn(222L);

        TestableConsumerCveService fallbackService =
                new TestableConsumerCveService(this.client, this.consumersIndex, this.environment);
        fallbackService.setConsumerService(this.consumerService);
        fallbackService.setSnapshotService(this.snapshotService);

        fallbackService.synchronize();

        InOrder inOrder = inOrder(this.snapshotService);
        inOrder.verify(this.snapshotService).initialize(eq(remoteConsumer));
        inOrder.verify(this.snapshotService).initialize(eq(localSnapshot), any());
    }

    /** Tests that a successful remote initialization removes the packaged local snapshot. */
    public void testSynchronizeDeletesLocalSnapshotAfterSuccessfulRemoteInitialization()
            throws Exception {
        Path pluginsDir = LuceneTestCase.createTempDir();
        Path localSnapshot =
                pluginsDir
                        .resolve(Constants.PLUGIN_DIR_NAME)
                        .resolve(Constants.CTI_SNAPSHOTS_DIR)
                        .resolve(Constants.CVE_SNAPSHOT_FILENAME);
        Files.createDirectories(localSnapshot.getParent());
        Files.writeString(localSnapshot, "placeholder");

        ConsumerCveServiceTests.clearPluginSettings();
        PluginSettings.getInstance(
                Settings.builder()
                        .put(
                                "plugins.content_manager.catalog.vulnerabilities",
                                "https://cti.example/api/v1/catalog/contexts/t1-vulnerabilities-5/consumers/public-vulnerabilities-5")
                        .build());

        RemoteConsumer remoteConsumer = mock(RemoteConsumer.class);

        when(this.environment.pluginsDir()).thenReturn(pluginsDir);
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);
        when(this.consumerService.getLocalConsumer()).thenReturn(null);
        when(this.consumerService.getRemoteConsumer()).thenReturn(remoteConsumer);
        when(remoteConsumer.getSnapshotLink())
                .thenReturn("https://cti.example/store/vulnerabilities.zip");
        when(remoteConsumer.getSnapshotOffset()).thenReturn(333L);
        when(remoteConsumer.getOffset()).thenReturn(333L);
        when(this.consumersIndex.getConsumer("cti:catalog:consumer:vulnerabilities"))
                .thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(false);
        when(this.snapshotService.initialize(eq(remoteConsumer))).thenReturn(true);

        TestableConsumerCveService fallbackService =
                new TestableConsumerCveService(this.client, this.consumersIndex, this.environment);
        fallbackService.setConsumerService(this.consumerService);
        fallbackService.setSnapshotService(this.snapshotService);

        fallbackService.synchronize();

        verify(this.snapshotService).initialize(eq(remoteConsumer));
        verify(this.snapshotService, never()).initialize(eq(localSnapshot), any());
        assertFalse(Files.exists(localSnapshot));
    }

    /**
     * Tests that status updates during synchronize preserve existing manifest-derived identity
     * fields.
     */
    public void testSynchronizePreservesExistingManifestIdentityFieldsInStatusUpdates()
            throws Exception {
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);
        when(this.consumerService.getLocalConsumer())
                .thenReturn(
                        new LocalConsumer(
                                "manifest-context",
                                "manifest-name",
                                "cti:catalog:consumer:vulnerabilities",
                                "https://manifest.example/resource",
                                true,
                                10,
                                10));
        when(this.consumerService.getRemoteConsumer()).thenReturn(null);

        when(this.consumersIndex.getConsumer("cti:catalog:consumer:vulnerabilities"))
                .thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString())
                .thenReturn(
                        "{\"name\":\"manifest-name\",\"context\":\"manifest-context\","
                                + "\"type\":\"cti:catalog:consumer:vulnerabilities\","
                                + "\"resource\":\"https://manifest.example/resource\","
                                + "\"is_public\":true,\"local_offset\":10,\"remote_offset\":10}");

        TestableConsumerCveService fallbackService =
                new TestableConsumerCveService(this.client, this.consumersIndex, this.environment);
        fallbackService.setConsumerService(this.consumerService);
        fallbackService.setSnapshotService(this.snapshotService);

        fallbackService.synchronize();

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex, org.mockito.Mockito.atLeast(2)).setConsumer(captor.capture());
        for (LocalConsumer persisted : captor.getAllValues()) {
            assertEquals("manifest-name", persisted.getName());
            assertEquals("manifest-context", persisted.getContext());
            assertEquals("https://manifest.example/resource", persisted.getResource());
            assertEquals("cti:catalog:consumer:vulnerabilities", persisted.getType());
        }
    }
}
