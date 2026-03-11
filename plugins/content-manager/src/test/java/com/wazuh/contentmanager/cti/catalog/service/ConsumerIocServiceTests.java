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

import org.apache.lucene.search.TotalHits;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.CreatePitAction;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.search.DeletePitAction;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.search.DocValueFormat;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
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

        // PITs should still be deleted despite the exception (hash + export both attempt PIT)
        verify(this.client, times(2))
                .execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));

        // Index should NOT have been called since the exception happened before indexing
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Tests that getContext returns the expected IOC context. */
    public void testGetContextReturnsExpectedValue() {
        assertEquals(PluginSettings.getInstance().getIocContext(), this.service.getContext());
    }

    /** Tests that getConsumer returns the expected IOC consumer. */
    public void testGetConsumerReturnsExpectedValue() {
        assertEquals(PluginSettings.getInstance().getIocConsumer(), this.service.getConsumer());
    }

    /** Tests that getMappings returns the IOC mappings. */
    public void testGetMappingsReturnsExpectedMappings() {
        Map<String, String> mappings = this.service.getMappings();

        assertNotNull(mappings);
        assertEquals(1, mappings.size());
        assertEquals("/mappings/cti-ioc-mappings.json", mappings.get(Constants.KEY_IOCS));
    }

    /** Tests that getAliases returns an empty map. */
    public void testGetAliasesReturnsEmpty() {
        Map<String, String> aliases = this.service.getAliases();

        assertNotNull(aliases);
        assertTrue(aliases.isEmpty());
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
}
