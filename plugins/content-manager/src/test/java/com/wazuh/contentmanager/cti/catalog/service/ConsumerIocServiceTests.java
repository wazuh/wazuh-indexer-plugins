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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.Level;
import org.apache.lucene.search.TotalHits;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.CreatePitAction;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.search.DeletePitAction;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.node.NodeClosedException;
import org.opensearch.search.DocValueFormat;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.ShardDocSortBuilder;
import org.opensearch.search.sort.SortBuilder;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.CapturingAppender;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.NodeShutdown;
import com.wazuh.contentmanager.utils.NodeShutdownTests;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ConsumerIocService}. Verifies per-type hash computation and storage using
 * mocked PIT and search operations.
 */
public class ConsumerIocServiceTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ConsumerIocService service;
    private AutoCloseable closeable;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private Client client;

    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;
    @Mock private EngineService engineService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);
        NodeShutdown.watch(NodeShutdownTests.idleComponent());
        when(this.environment.tmpDir()).thenReturn(LuceneTestCase.createTempDir());
        when(this.environment.sharedDataDir()).thenReturn(LuceneTestCase.createTempDir());

        Path tempHome = LuceneTestCase.createTempDir();
        Files.createDirectories(tempHome.resolve("engine").resolve("data"));
        Settings testSettings = Settings.builder().put("path.home", tempHome.toString()).build();
        when(this.environment.settings()).thenReturn(testSettings);

        when(this.engineService.getIocState())
                .thenReturn(new RestResponse("{\"hash\":\"abc\",\"updating\":false}", 200));
        when(this.engineService.updateIoc(anyString(), anyString()))
                .thenReturn(new RestResponse("OK", 200));
        this.service =
                new ConsumerIocService(
                        this.client, this.consumersIndex, this.environment, this.engineService);
    }

    /**
     * The IoC consumer's single target index is reported missing when nothing answers to its name, so
     * the synchronization pass can defer instead of letting a write auto-create a dynamically mapped
     * index under the alias name (issues #1476 and #1481).
     */
    public void testMissingTargetIndicesReportsTheAbsentIndex() {
        when(this.client.admin().indices().prepareExists(Constants.INDEX_IOCS).get().isExists())
                .thenReturn(false);

        Assert.assertEquals(List.of(Constants.INDEX_IOCS), this.service.missingTargetIndices());
    }

    /** Nothing is reported missing once the Setup plugin has provisioned the index. */
    public void testMissingTargetIndicesIsEmptyWhenTheIndexExists() {
        when(this.client.admin().indices().prepareExists(Constants.INDEX_IOCS).get().isExists())
                .thenReturn(true);

        Assert.assertTrue(this.service.missingTargetIndices().isEmpty());
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
     * Creates a SearchHit with the given id, type, and SHA-256 hash. Sort values are set to [type,
     * id] for the single-pass sorted iteration.
     */
    private SearchHit createIocHit(int docId, String id, String type, String sha256) {
        String source =
                "{\"document\":{\"type\":\"" + type + "\"},\"hash\":{\"sha256\":\"" + sha256 + "\"}}";
        SearchHit hit = new SearchHit(docId, id, Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(new org.opensearch.core.common.bytes.BytesArray(source));
        hit.sortValues(
                new Object[] {type, id}, new DocValueFormat[] {DocValueFormat.RAW, DocValueFormat.RAW});
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

    /** Mocks a search that returns no documents, so the single pass terminates immediately. */
    @SuppressWarnings("unchecked")
    private void mockEmptySearch() {
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(emptyFuture);
    }

    /**
     * Mocks PIT creation, and PIT release such that the release identified by {@code failingRelease}
     * (1-based: 1 is the hash pass, 2 is the export) fails the way a node leaving the cluster
     * mid-sync makes it fail.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void mockPitLifecycleWithFailingRelease(int failingRelease) {
        CreatePitResponse pitResponse = mock(CreatePitResponse.class);
        when(pitResponse.getId()).thenReturn("test-pit-id");
        ActionFuture<CreatePitResponse> pitFuture = mock(ActionFuture.class);
        when(pitFuture.actionGet()).thenReturn(pitResponse);
        when(this.client.execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class)))
                .thenReturn(pitFuture);

        ActionFuture<Object> okFuture = mock(ActionFuture.class);
        ActionFuture<Object> failingFuture = mock(ActionFuture.class);
        when(failingFuture.actionGet())
                .thenThrow(new RuntimeException("[node-8][172.31.33.24:9300] Node not connected"));

        when(this.client.execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class)))
                .thenReturn(
                        (ActionFuture) (failingRelease == 1 ? failingFuture : okFuture),
                        (ActionFuture) (failingRelease == 2 ? failingFuture : okFuture));
    }

    /** Tests that onSyncComplete does nothing when isUpdated is false. */
    public void testOnSyncCompleteSkipsWhenNotUpdated() {
        this.service.onSyncComplete(false);

        verify(this.client, never()).execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
    }

    /** Tests that onSyncComplete computes and stores hashes when isUpdated is true. */
    @SuppressWarnings("unchecked")
    public void testOnSyncCompleteComputesHashesWhenUpdated() {
        this.mockPitLifecycle();

        // Single-pass search returns empty hits (no documents)
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(emptyFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        // Verify PITs were created and deleted (hash computation + export)
        verify(this.client, times(2))
                .execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
        verify(this.client, times(2))
                .execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));

        // Verify hash document was indexed with the correct ID
        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        IndexRequest capturedRequest = indexCaptor.getValue();
        assertEquals(Constants.INDEX_IOCS, capturedRequest.index());
        assertEquals(Constants.IOC_TYPE_HASHES_ID, capturedRequest.id());
    }

    /** Tests that the hash document contains discovered types under type_hashes wrapper. */
    @SuppressWarnings("unchecked")
    public void testHashDocumentContainsDiscoveredTypes() throws Exception {
        this.mockPitLifecycle();

        String[] types = {"connection", "hash_md5", "url-full"};

        // Build hits for three types, sorted by type ASC then _id ASC
        SearchHit hit1 = this.createIocHit(1, "doc-1", "connection", "aaa111");
        SearchHit hit2 = this.createIocHit(2, "doc-2", "hash_md5", "bbb222");
        SearchHit hit3 = this.createIocHit(3, "doc-3", "url-full", "ccc333");

        SearchHits pageHits =
                new SearchHits(
                        new SearchHit[] {hit1, hit2, hit3},
                        new TotalHits(3, TotalHits.Relation.EQUAL_TO),
                        1.0f);
        SearchResponse pageResponse = mock(SearchResponse.class);
        when(pageResponse.getHits()).thenReturn(pageHits);

        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());

        ActionFuture<SearchResponse> pageFuture = mock(ActionFuture.class);
        when(pageFuture.actionGet()).thenReturn(pageResponse);
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(pageFuture)
                .thenReturn(emptyFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        JsonNode root = MAPPER.readTree(source);
        assertTrue("Document should have type_hashes wrapper", root.has(Constants.KEY_TYPE_HASHES));
        JsonNode typeHashes = root.get(Constants.KEY_TYPE_HASHES);

        for (String type : types) {
            assertTrue("type_hashes should contain type '" + type + "'", typeHashes.has(type));
            assertTrue(
                    "Type '" + type + "' should have hash.sha256",
                    typeHashes.path(type).path(Constants.KEY_HASH).has(Constants.KEY_SHA256));
        }
    }

    /** Tests hash computation with actual IOC documents. */
    @SuppressWarnings("unchecked")
    public void testHashComputationWithDocuments() {
        this.mockPitLifecycle();

        // Build a search response with one hit for the "connection" type
        String connDocHash = "abc123def456";
        SearchHit connHit = this.createIocHit(1, "doc-1", "connection", connDocHash);
        SearchHits connHits =
                new SearchHits(
                        new SearchHit[] {connHit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);

        SearchResponse connSearchResponse = mock(SearchResponse.class);
        when(connSearchResponse.getHits()).thenReturn(connHits);
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());

        ActionFuture<SearchResponse> connSearchFuture = mock(ActionFuture.class);
        when(connSearchFuture.actionGet()).thenReturn(connSearchResponse);
        ActionFuture<SearchResponse> emptySearchFuture = mock(ActionFuture.class);
        when(emptySearchFuture.actionGet()).thenReturn(emptySearchResponse);

        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(connSearchFuture) // page 1 with document
                .thenReturn(emptySearchFuture); // page 2 (empty = done)

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        // Verify the hash for connection differs from the empty hash
        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        String expectedConnHash = Resource.computeSha256(connDocHash);
        String emptyHash = Resource.computeSha256("");
        assertNotEquals("connection hash should differ from empty hash", expectedConnHash, emptyHash);
        assertTrue(
                "Hash document should contain the computed connection hash",
                source.contains(expectedConnHash));
    }

    /** Tests that the PIT is deleted even when an exception occurs during hash computation. */
    @SuppressWarnings("unchecked")
    public void testPitDeletedOnException() {
        this.mockPitLifecycle();

        // Mock search to throw an exception
        when(this.client.search(any(SearchRequest.class)))
                .thenThrow(new RuntimeException("Search failed"));

        // Should not throw — exception is caught internally
        this.service.onSyncComplete(true);

        // The hash pass's PIT is still deleted despite the exception. The export never opens one:
        // without the hashes there is nothing to hand the Engine.
        verify(this.client, times(1))
                .execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
        verify(this.client, times(1))
                .execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));

        // Index should NOT have been called since the exception happened before indexing
        verify(this.client, never()).index(any(IndexRequest.class));
        verify(this.engineService, never()).updateIoc(anyString(), anyString());
    }

    /**
     * Stubs {@code consumersIndex.getConsumer(...)} to return an IOC consumer document with the given
     * pending phases.
     */
    private void mockExistingConsumerDoc(List<String> pendingPhases) throws Exception {
        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(true);
        when(response.getSourceAsString())
                .thenReturn(
                        "{\"name\":\"iocs\",\"context\":\"ctx\",\"status\":\"ready\","
                                + "\"type\":\"cti:catalog:consumer:iocs\","
                                + "\"resource\":\"\",\"is_public\":true,"
                                + "\"local_offset\":42,\"remote_offset\":42,"
                                + "\"pending_sync_phases\":"
                                + MAPPER.writeValueAsString(pendingPhases)
                                + "}");
        when(this.consumersIndex.getConsumer(any())).thenReturn(response);
    }

    /** Returns the pending phases of the last consumer document written. */
    private List<String> lastWrittenPendingPhases() throws Exception {
        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
        return captor.getValue().getPendingSyncPhases();
    }

    /** A content change owes the IOC load, so it is recorded before the content changes. */
    public void testContentChangeOwesIocLoad() {
        assertEquals(
                List.of(ConsumerIocService.PHASE_IOC_LOAD), this.service.phasesOwedByContentChange());
    }

    /**
     * A load left pending by a pass that was cut, for instance by the node stopping after the content
     * was written, runs on the next pass even though the offsets are already up to date, and is
     * cleared once it has run.
     */
    public void testPendingLoadRunsWithoutUpdateAndIsCleared() throws Exception {
        this.mockExistingConsumerDoc(List.of(ConsumerIocService.PHASE_IOC_LOAD));
        this.mockPitLifecycle();
        this.mockEmptySearch();
        this.mockIndexResponse();

        this.service.onSyncComplete(false);

        verify(this.client).index(any(IndexRequest.class));
        verify(this.engineService).updateIoc(anyString(), anyString());
        assertEquals(List.of(), this.lastWrittenPendingPhases());
    }

    /** A pass with nothing new and nothing pending leaves the pending phases untouched. */
    public void testNothingPendingWritesNothing() throws Exception {
        this.mockExistingConsumerDoc(List.of());

        this.service.onSyncComplete(false);

        verify(this.client, never()).execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
        verify(this.consumersIndex, never()).setConsumer(any());
    }

    /** Failed hashes skip the export and leave the load pending for the next pass. */
    public void testFailedHashesKeepLoadPending() throws Exception {
        this.mockExistingConsumerDoc(List.of(ConsumerIocService.PHASE_IOC_LOAD));
        this.mockPitLifecycle();
        when(this.client.search(any(SearchRequest.class)))
                .thenThrow(new RuntimeException("Search failed"));

        this.service.onSyncComplete(false);

        verify(this.engineService, never()).updateIoc(anyString(), anyString());
        verify(this.consumersIndex, never()).setConsumer(any());
    }

    /** A failed export leaves the load pending, with the hashes already stored. */
    @SuppressWarnings("unchecked")
    public void testFailedExportKeepsLoadPending() throws Exception {
        this.mockExistingConsumerDoc(List.of(ConsumerIocService.PHASE_IOC_LOAD));
        this.mockPitLifecycle();
        this.mockIndexResponse();
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
        ActionFuture<SearchResponse> failingFuture = mock(ActionFuture.class);
        when(failingFuture.actionGet()).thenThrow(new RuntimeException("Search failed"));
        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(emptyFuture) // hash pass
                .thenReturn(failingFuture); // export

        this.service.onSyncComplete(false);

        verify(this.client).index(any(IndexRequest.class));
        verify(this.engineService, never()).updateIoc(anyString(), anyString());
        verify(this.consumersIndex, never()).setConsumer(any());
    }

    /**
     * The Engine's answer does not keep the load pending: the node holding the sync may have no
     * Engine, and the load would otherwise be retried on every pass.
     */
    public void testEngineRefusalDoesNotKeepLoadPending() throws Exception {
        this.mockExistingConsumerDoc(List.of(ConsumerIocService.PHASE_IOC_LOAD));
        this.mockPitLifecycle();
        this.mockEmptySearch();
        this.mockIndexResponse();
        when(this.engineService.updateIoc(anyString(), anyString()))
                .thenReturn(new RestResponse("Engine unavailable", 503));

        this.service.onSyncComplete(false);

        assertEquals(List.of(), this.lastWrittenPendingPhases());
    }

    /**
     * Failures caused by the node stopping are logged at debug, not as errors: here the hash pass's
     * point-in-time search and the status writes after it, as in the stop window of
     * wazuh-indexer#2029.
     */
    public void testShutdownFailureIsNotLoggedAsError() {
        this.mockPitLifecycle();
        when(this.client.search(any(SearchRequest.class)))
                .thenThrow(new RuntimeException(new NodeClosedException((DiscoveryNode) null)));

        try (CapturingAppender appender = CapturingAppender.attach(ConsumerIocService.class)) {
            this.service.onSyncComplete(true);

            assertEquals(0, appender.count(Level.ERROR));
            assertEquals(0, appender.count(Level.WARN));
        }
    }

    /**
     * While the node stops, the PIT is not released: its contexts close with the node, and core logs
     * {@code PitService} "Delete PITs failed" at error for a release that can only fail.
     */
    public void testPitNotReleasedWhileNodeStops() {
        AbstractLifecycleComponent clusterService = NodeShutdownTests.idleComponent();
        NodeShutdown.watch(clusterService);
        clusterService.start();
        clusterService.stop();
        this.mockPitLifecycle();
        when(this.client.search(any(SearchRequest.class)))
                .thenThrow(new RuntimeException(new NodeClosedException((DiscoveryNode) null)));

        this.service.onSyncComplete(true);

        verify(this.client).execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
        verify(this.client, never()).execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));
    }

    /** The same failure on a running node is still an error. */
    public void testRealFailureIsLoggedAsError() {
        this.mockPitLifecycle();
        when(this.client.search(any(SearchRequest.class)))
                .thenThrow(new RuntimeException("Search failed"));

        try (CapturingAppender appender = CapturingAppender.attach(ConsumerIocService.class)) {
            this.service.onSyncComplete(true);

            assertEquals(1, appender.count(Level.ERROR));
        }
    }

    /**
     * A failing PIT release during the hash pass must not abort the rest of the post-sync cascade.
     * The release sits in a {@code finally} whose {@code try} already catches everything, so before
     * this was guarded it was the only statement that could throw out of {@code
     * computeAndStoreTypeHashes()}: the failure propagated through {@code onSyncComplete()} into
     * {@code AbstractConsumerService.synchronize()}, which marks the consumer FAILED, and the export
     * and Engine notification that follow it never ran. Releasing a PIT is best-effort — the context
     * expires on its own keepalive, and one held by a departed node died with it.
     */
    @SuppressWarnings("unchecked")
    public void testHashPassPitReleaseFailureStillExportsAndNotifiesEngine() {
        this.mockPitLifecycleWithFailingRelease(1);
        this.mockEmptySearch();
        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        verify(this.client).index(any(IndexRequest.class));
        verify(this.client, times(2))
                .execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));
        verify(this.engineService).updateIoc(anyString(), anyString());
    }

    /**
     * The same for the export's PIT, which is released after the NDJSON file has been written but
     * before {@code export()} returns its path. A failing release used to discard a completed export
     * and, with it, the Engine notification.
     */
    @SuppressWarnings("unchecked")
    public void testExportPitReleaseFailureStillNotifiesEngine() {
        this.mockPitLifecycleWithFailingRelease(2);
        this.mockEmptySearch();
        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        verify(this.client, times(2))
                .execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));
        verify(this.engineService).updateIoc(anyString(), anyString());
    }

    /** Tests that getMappings returns the IOC mappings. */
    public void testGetMappingsReturnsExpectedMappings() {
        Map<String, String> mappings = this.service.getMappings();

        assertNotNull(mappings);
        assertEquals(1, mappings.size());
        assertEquals("/mappings/cti-ioc-mappings.json", mappings.get(Constants.KEY_IOCS));
    }

    /** Tests that when no documents exist, an empty type_hashes document is stored. */
    /** Tests that onSyncComplete(true) calls engineService.loadIocs after export. */
    @SuppressWarnings("unchecked")
    public void testOnSyncCompleteNotifiesEngine() {
        // Mock PIT creation
        CreatePitResponse pitResponse = mock(CreatePitResponse.class);
        when(pitResponse.getId()).thenReturn("test-pit-id");
        ActionFuture<CreatePitResponse> pitFuture = mock(ActionFuture.class);
        when(pitFuture.actionGet()).thenReturn(pitResponse);
        when(this.client.execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class)))
                .thenReturn(pitFuture);

        // Mock search returning empty results
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        when(searchFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        // Mock index response
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenReturn(mock(IndexResponse.class));
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Mock PIT deletion
        ActionFuture<?> deletePitFuture = mock(ActionFuture.class);
        when(this.client.execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class)))
                .thenReturn((ActionFuture) deletePitFuture);

        this.service.onSyncComplete(true);

        verify(this.engineService).updateIoc(anyString(), anyString());
    }

    /** Tests that onSyncComplete(false) does not call engineService.loadIocs. */
    public void testOnSyncCompleteDoesNotNotifyEngineWhenNotUpdated() {
        this.service.onSyncComplete(false);

        verify(this.engineService, never()).updateIoc(anyString(), anyString());
    }

    /** Tests that engine notification failure does not propagate as an exception. */
    @SuppressWarnings("unchecked")
    public void testEngineNotificationFailureDoesNotPropagate() {
        // Override the engineService mock to return an error
        when(this.engineService.updateIoc(anyString(), anyString()))
                .thenReturn(new RestResponse("Engine error", 500));

        // Mock PIT creation
        CreatePitResponse pitResponse = mock(CreatePitResponse.class);
        when(pitResponse.getId()).thenReturn("test-pit-id");
        ActionFuture<CreatePitResponse> pitFuture = mock(ActionFuture.class);
        when(pitFuture.actionGet()).thenReturn(pitResponse);
        when(this.client.execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class)))
                .thenReturn(pitFuture);

        // Mock search returning empty results
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        when(searchFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        // Mock index response
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenReturn(mock(IndexResponse.class));
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Mock PIT deletion
        ActionFuture<?> deletePitFuture = mock(ActionFuture.class);
        when(this.client.execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class)))
                .thenReturn((ActionFuture) deletePitFuture);

        // Should not throw — engine error is handled internally
        this.service.onSyncComplete(true);

        verify(this.engineService).updateIoc(anyString(), anyString());
    }

    /** Tests that loadIocs is NOT called when Engine reports updating=true. */
    @SuppressWarnings("unchecked")
    public void testNotifyEngineSkippedWhenEngineIsUpdating() {
        when(this.engineService.getIocState())
                .thenReturn(new RestResponse("{\"hash\":\"abc\",\"updating\":true}", 200));

        this.mockPitLifecycle();

        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        when(searchFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        verify(this.engineService).getIocState();
        verify(this.engineService, never()).updateIoc(anyString(), anyString());
    }

    /** Tests that loadIocs IS called when Engine reports updating=false. */
    @SuppressWarnings("unchecked")
    public void testNotifyEngineCalledWhenEngineIsNotUpdating() {
        when(this.engineService.getIocState())
                .thenReturn(new RestResponse("{\"hash\":\"abc\",\"updating\":false}", 200));

        this.mockPitLifecycle();

        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        when(searchFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        verify(this.engineService).getIocState();
        verify(this.engineService).updateIoc(anyString(), anyString());
    }

    /** Tests that loadIocs is NOT called when the state check fails (fail-closed). */
    @SuppressWarnings("unchecked")
    public void testNotifyEngineSkippedWhenStateCheckFails() {
        when(this.engineService.getIocState()).thenReturn(new RestResponse("Engine error", 500));

        this.mockPitLifecycle();

        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        when(searchFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        verify(this.engineService).getIocState();
        verify(this.engineService, never()).updateIoc(anyString(), anyString());
    }

    /**
     * Tests that when INDEXER_TEST_ENV=true, the export and engine notification are skipped after
     * hash computation completes. Only one PIT should be created (for hash computation), and
     * engineService.updateIoc should never be called.
     */
    @SuppressForbidden(reason = "Setting system property required to test INDEXER_TEST_ENV gate")
    @SuppressWarnings("unchecked")
    public void testOnSyncCompleteSkipsExportInTestEnvironment() {
        System.setProperty("INDEXER_TEST_ENV", "true");
        try {
            this.mockPitLifecycle();

            // Mock search returning empty results (hash computation finds no docs)
            SearchResponse emptySearchResponse = mock(SearchResponse.class);
            when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
            ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
            when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
            when(this.client.search(any(SearchRequest.class))).thenReturn(emptyFuture);

            this.mockIndexResponse();

            this.service.onSyncComplete(true);

            // Only one PIT should be created (hash computation), not a second one for export
            verify(this.client, times(1))
                    .execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
            verify(this.client, times(1))
                    .execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));

            // Engine should never be notified
            verify(this.engineService, never()).updateIoc(anyString(), anyString());
            verify(this.engineService, never()).getIocState();
        } finally {
            System.clearProperty("INDEXER_TEST_ENV");
        }
    }

    /** Tests that search is paginated — one search per type (all empty) plus no extra. */
    @SuppressWarnings("unchecked")
    public void testEmptyIndexProducesEmptyTypeHashes() throws Exception {
        this.mockPitLifecycle();

        // Search returns no hits
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(emptyFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        JsonNode root = MAPPER.readTree(source);
        assertTrue("Document should have type_hashes wrapper", root.has(Constants.KEY_TYPE_HASHES));
        assertEquals(
                "type_hashes should be empty when no documents exist",
                0,
                root.get(Constants.KEY_TYPE_HASHES).size());
    }

    /**
     * Both IoC passes sort on {@code document.id} with a {@code _shard_doc} tiebreaker, never on
     * {@code _id}: an {@code _id} sort has no doc values and makes every page expensive enough for
     * search backpressure to cancel it on a busy node (wazuh-indexer#2007). The hash pass also
     * fetches only the two fields it reads.
     */
    public void testIocPassesSortOnDocValuesFields() {
        this.mockPitLifecycle();
        this.mockEmptySearch();
        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        ArgumentCaptor<SearchRequest> searchCaptor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(this.client, times(2)).search(searchCaptor.capture());
        SearchRequest hashPass = searchCaptor.getAllValues().get(0);
        SearchRequest exportPass = searchCaptor.getAllValues().get(1);

        assertEquals(
                List.of(Constants.Q_DOCUMENT_TYPE, Constants.Q_DOCUMENT_ID, "_shard_doc"),
                sortKeys(hashPass));
        assertEquals(List.of(Constants.Q_DOCUMENT_ID, "_shard_doc"), sortKeys(exportPass));
        assertArrayEquals(
                new String[] {Constants.Q_DOCUMENT_TYPE, Constants.Q_HASH},
                hashPass.source().fetchSource().includes());
        assertEquals(1_000, hashPass.source().size());
    }

    private static List<String> sortKeys(SearchRequest request) {
        return request.source().sorts().stream()
                .map(ConsumerIocServiceTests::sortKey)
                .collect(Collectors.toList());
    }

    private static String sortKey(SortBuilder<?> sort) {
        if (sort instanceof FieldSortBuilder field) {
            return field.getFieldName();
        }
        if (sort instanceof ShardDocSortBuilder) {
            return ShardDocSortBuilder.NAME;
        }
        return sort.toString();
    }
}
