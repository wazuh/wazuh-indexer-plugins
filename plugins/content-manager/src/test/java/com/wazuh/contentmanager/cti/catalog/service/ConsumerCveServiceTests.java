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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.client.ResourceUrlResolver;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
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
        assertEquals("/mappings/cti-cve-mappings.json", mappings.get(Constants.KEY_CVES));
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
        boolean feedUnreachable = fallbackService.synchronize();

        assertTrue(
                "A configured feed that could not be reached must be reported as unreachable so the"
                        + " job retries, even though the local snapshot fallback succeeded",
                feedUnreachable);
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

        boolean feedUnreachable = fallbackService.synchronize();

        assertFalse("A reachable feed must not be reported as unreachable", feedUnreachable);
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

    /**
     * Tests that synchronize() does not report the consumer as ready when its target index has not
     * been provisioned yet. This is the exact condition that let a CI run observe the vulnerabilities
     * consumer as "ready" while {@code .wazuh-threatintel-vulnerabilities} still did not exist — a
     * startup race between the Setup plugin finishing index provisioning and the first catalog sync.
     * Nothing was synced, so the status must stay at {@link LocalConsumer.Status#RUNNING} (set at the
     * top of {@code synchronize()}) rather than jump to {@link LocalConsumer.Status#READY}, and the
     * caller must be told to retry immediately instead of waiting for the next scheduled sync.
     */
    public void testSynchronizeDoesNotReportReadyWhenTargetIndexIsMissing() throws Exception {
        when(this.client.admin().indices().prepareExists(Constants.INDEX_CVES).get().isExists())
                .thenReturn(false);
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

        TestableConsumerCveService service =
                new TestableConsumerCveService(this.client, this.consumersIndex, this.environment);
        service.setConsumerService(this.consumerService);
        service.setSnapshotService(this.snapshotService);

        boolean needsRetry = service.synchronize();

        assertTrue(
                "a pass aborted because target indices are missing must be retried immediately rather"
                        + " than waiting for the next scheduled sync",
                needsRetry);

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex, org.mockito.Mockito.atLeastOnce()).setConsumer(captor.capture());
        for (LocalConsumer persisted : captor.getAllValues()) {
            assertEquals(
                    "status must stay RUNNING, never READY, when nothing was actually synced",
                    LocalConsumer.Status.RUNNING,
                    persisted.getStatus());
        }
        verify(this.snapshotService, never()).initialize(any(RemoteConsumer.class));
        verify(this.snapshotService, never()).initialize(any(Path.class), any());
    }

    // ---------------------------------------------------------------------
    // An offset that cannot be applied falls back to a snapshot (#1633).
    // ---------------------------------------------------------------------

    private static final String VD_CATALOG_URI =
            "https://cti.example/api/v1/catalog/contexts/t1-vulnerabilities-5/consumers/public-vulnerabilities-5";

    /**
     * A ConsumerCveService whose incremental updates and shadow swaps are scripted instead of calling
     * CTI and the cluster.
     */
    private static class ScriptedConsumerCveService extends TestableConsumerCveService {
        final List<long[]> incrementalUpdates = new ArrayList<>();
        final List<String> shadowSwaps = new ArrayList<>();
        private final RuntimeException firstFailure;
        private final boolean swapSucceeds;

        ScriptedConsumerCveService(
                Client client,
                ConsumersIndex consumersIndex,
                Environment environment,
                RuntimeException firstFailure,
                boolean swapSucceeds) {
            super(client, consumersIndex, environment);
            this.firstFailure = firstFailure;
            this.swapSucceeds = swapSucceeds;
        }

        @Override
        boolean performIncrementalUpdate(
                String context,
                String consumer,
                String consumerType,
                String catalogUri,
                ResourceUrlResolver urlResolver,
                Map<String, ContentIndex> indicesMap,
                long fromOffset,
                long toOffset) {
            this.incrementalUpdates.add(new long[] {fromOffset, toOffset});
            if (this.incrementalUpdates.size() == 1) {
                throw this.firstFailure;
            }
            return true;
        }

        @Override
        boolean performShadowSwap(
                String consumerType,
                String catalogUri,
                String planResource,
                Map<String, ContentIndex> liveIndicesMap,
                RemoteConsumer remoteConsumer,
                ResourceUrlResolver urlResolver) {
            this.shadowSwaps.add(planResource);
            return this.swapSucceeds;
        }
    }

    /**
     * The failure UpdateServiceImpl reports when the change at the given offset cannot be applied.
     */
    private static RuntimeException patchFailureAt(long offset) {
        return new RuntimeException(
                "Update failed for consumer [cti:catalog:consumer:vulnerabilities]",
                new ContentIndex.PatchException(
                        "CVE-2026-90029", offset, "operation 0 (remove /x): no such path", null));
    }

    /**
     * A consumer that starts its pass at offset 1000 and whose first incremental update fails as
     * given, against a remote head at 1060 whose latest snapshot is at the given offset.
     *
     * @param persistedLocalOffset The local offset in the consumer document after the failure (the
     *     update's checkpoint), or null for no document.
     */
    private ScriptedConsumerCveService consumerStuckAt1000(
            long snapshotOffset,
            RuntimeException failure,
            RemoteConsumer remoteConsumer,
            Long persistedLocalOffset,
            boolean swapSucceeds)
            throws Exception {
        ConsumerCveServiceTests.clearPluginSettings();
        PluginSettings.getInstance(
                Settings.builder()
                        .put("plugins.content_manager.catalog.vulnerabilities", VD_CATALOG_URI)
                        .build());
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);
        when(this.consumerService.getLocalConsumer())
                .thenReturn(
                        new LocalConsumer(
                                "t1-vulnerabilities-5",
                                "public-vulnerabilities-5",
                                "cti:catalog:consumer:vulnerabilities",
                                VD_CATALOG_URI,
                                true,
                                LocalConsumer.Status.FAILED,
                                1000,
                                1050));
        when(this.consumerService.getRemoteConsumer()).thenReturn(remoteConsumer);
        when(remoteConsumer.getSnapshotLink()).thenReturn("https://cti.example/store/snapshot.zip");
        when(remoteConsumer.getSnapshotOffset()).thenReturn(snapshotOffset);
        when(remoteConsumer.getOffset()).thenReturn(1060L);
        when(this.consumersIndex.getConsumer("cti:catalog:consumer:vulnerabilities"))
                .thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(persistedLocalOffset != null);
        if (persistedLocalOffset != null) {
            when(this.getResponse.getSourceAsString())
                    .thenReturn(
                            "{\"name\":\"public-vulnerabilities-5\",\"context\":\"t1-vulnerabilities-5\","
                                    + "\"type\":\"cti:catalog:consumer:vulnerabilities\",\"resource\":\""
                                    + VD_CATALOG_URI
                                    + "\",\"is_public\":true,\"status\":\"running\",\"local_offset\":"
                                    + persistedLocalOffset
                                    + ",\"remote_offset\":1060}");
        }

        ScriptedConsumerCveService service =
                new ScriptedConsumerCveService(
                        this.client, this.consumersIndex, this.environment, failure, swapSucceeds);
        service.setConsumerService(this.consumerService);
        service.setSnapshotService(this.snapshotService);
        return service;
    }

    /**
     * A snapshot past the offset that cannot be applied: the same pass rebuilds the content from it,
     * through a shadow swap that keeps the source, and applies the remaining changes from the
     * snapshot's offset.
     */
    public void testPatchFailureRebuildsFromSnapshotThatIncludesTheOffset() throws Exception {
        ScriptedConsumerCveService service =
                this.consumerStuckAt1000(
                        1050L, patchFailureAt(1030L), mock(RemoteConsumer.class), null, true);

        boolean needsRetry = service.synchronize();

        assertFalse(needsRetry);
        assertEquals(List.of(VD_CATALOG_URI), service.shadowSwaps);
        assertEquals(2, service.incrementalUpdates.size());
        assertArrayEquals(new long[] {1000, 1060}, service.incrementalUpdates.get(0));
        assertArrayEquals(new long[] {1050, 1060}, service.incrementalUpdates.get(1));
        // The content is never cleared in place: the snapshot goes through the shadow indices.
        verify(this.snapshotService, never()).initialize(any(RemoteConsumer.class));
    }

    /**
     * A snapshot newer than the local offset but older than the failing one still rebuilds the
     * content: stored content that diverged from CTI is what makes a valid change fail.
     */
    public void testPatchFailureRebuildsFromSnapshotNewerThanLocalOffset() throws Exception {
        ScriptedConsumerCveService service =
                this.consumerStuckAt1000(
                        1020L, patchFailureAt(1030L), mock(RemoteConsumer.class), null, true);

        service.synchronize();

        assertEquals(1, service.shadowSwaps.size());
        assertArrayEquals(new long[] {1020, 1060}, service.incrementalUpdates.get(1));
    }

    /** No snapshot newer than the local offset: nothing is rebuilt and the failure propagates. */
    public void testPatchFailureWithoutNewerSnapshotDoesNotRebuild() throws Exception {
        ScriptedConsumerCveService service =
                this.consumerStuckAt1000(
                        1000L, patchFailureAt(1030L), mock(RemoteConsumer.class), null, true);

        expectThrows(RuntimeException.class, service::synchronize);

        assertTrue(service.shadowSwaps.isEmpty());
        assertEquals(1, service.incrementalUpdates.size());
    }

    /**
     * The local offset is the update's checkpoint, which can be past the offset the pass started
     * from: a snapshot between the two is already behind the content and is not loaded.
     */
    public void testPatchFailureComparesSnapshotWithCheckpoint() throws Exception {
        ScriptedConsumerCveService service =
                this.consumerStuckAt1000(
                        1015L, patchFailureAt(1030L), mock(RemoteConsumer.class), 1020L, true);

        expectThrows(RuntimeException.class, service::synchronize);

        assertTrue(service.shadowSwaps.isEmpty());
    }

    /**
     * The snapshot cannot be loaded: the shadow swap keeps the current content, nothing more is
     * applied, and the failure propagates.
     */
    public void testPatchFailureKeepsContentWhenSnapshotCannotBeLoaded() throws Exception {
        ScriptedConsumerCveService service =
                this.consumerStuckAt1000(
                        1050L, patchFailureAt(1030L), mock(RemoteConsumer.class), null, false);

        expectThrows(RuntimeException.class, service::synchronize);

        assertEquals(1, service.shadowSwaps.size());
        assertEquals(1, service.incrementalUpdates.size());
        verify(this.snapshotService, never()).initialize(any(RemoteConsumer.class));
    }

    /** Any other failure, here a CTI error, propagates without touching the content. */
    public void testNonPatchFailureDoesNotRebuild() throws Exception {
        ScriptedConsumerCveService service =
                this.consumerStuckAt1000(
                        1050L,
                        new RuntimeException("Failed to fetch changes (HTTP 500)"),
                        mock(RemoteConsumer.class),
                        null,
                        true);

        expectThrows(RuntimeException.class, service::synchronize);

        assertTrue(service.shadowSwaps.isEmpty());
        assertEquals(1, service.incrementalUpdates.size());
    }
}
