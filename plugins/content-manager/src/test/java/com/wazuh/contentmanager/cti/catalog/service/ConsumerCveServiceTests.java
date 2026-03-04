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

import java.util.Collections;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ConsumerCveService}. Verifies global hash computation and storage using
 * mocked PIT and search operations.
 */
public class ConsumerCveServiceTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ConsumerCveService service;
    private AutoCloseable closeable;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private Client client;

    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);
        this.service = new ConsumerCveService(this.client, this.consumersIndex, this.environment);
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

    /** Tests that onSyncComplete computes and stores hash when isUpdated is true. */
    @SuppressWarnings("unchecked")
    public void testOnSyncCompleteComputesHashWhenUpdated() {
        this.mockPitLifecycle();

        // Single-pass search returns empty hits (no documents)
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(emptyFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        // Verify PIT was created and deleted
        verify(this.client).execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
        verify(this.client).execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));

        // Verify hash document was indexed with the correct ID
        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        IndexRequest capturedRequest = indexCaptor.getValue();
        assertEquals(Constants.INDEX_CVES, capturedRequest.index());
        assertEquals(Constants.CVE_HASH_ID, capturedRequest.id());
    }

    /** Tests that the hash document contains a single global hash. */
    @SuppressWarnings("unchecked")
    public void testHashDocumentContainsGlobalHash() throws Exception {
        this.mockPitLifecycle();

        // Build hits for three CVEs
        SearchHit hit1 = this.createCveHit(1, "CVE-2024-0001", "aaa111");
        SearchHit hit2 = this.createCveHit(2, "CVE-2024-0002", "bbb222");
        SearchHit hit3 = this.createCveHit(3, "CVE-2024-0003", "ccc333");

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
        assertTrue("Document should have hash wrapper", root.has(Constants.KEY_HASH));
        JsonNode hash = root.get(Constants.KEY_HASH);
        assertTrue("Hash should contain sha256", hash.has(Constants.KEY_SHA256));
        assertNotNull("sha256 should have a value", hash.get(Constants.KEY_SHA256).asText());
    }

    /** Tests hash computation with actual CVE documents. */
    @SuppressWarnings("unchecked")
    public void testHashComputationWithDocuments() {
        this.mockPitLifecycle();

        // Build a search response with one CVE hit
        String cveDocHash = "abc123def456";
        SearchHit cveHit = this.createCveHit(1, "CVE-2024-0001", cveDocHash);
        SearchHits cveHits =
                new SearchHits(
                        new SearchHit[] {cveHit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);

        SearchResponse cveSearchResponse = mock(SearchResponse.class);
        when(cveSearchResponse.getHits()).thenReturn(cveHits);
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());

        ActionFuture<SearchResponse> cveSearchFuture = mock(ActionFuture.class);
        when(cveSearchFuture.actionGet()).thenReturn(cveSearchResponse);
        ActionFuture<SearchResponse> emptySearchFuture = mock(ActionFuture.class);
        when(emptySearchFuture.actionGet()).thenReturn(emptySearchResponse);

        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(cveSearchFuture) // page 1 with document
                .thenReturn(emptySearchFuture); // page 2 (empty = done)

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        // Verify the hash for CVE differs from the empty hash
        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        String expectedHash = Resource.computeSha256(cveDocHash);
        String emptyHash = Resource.computeSha256("");
        assertNotEquals("CVE hash should differ from empty hash", expectedHash, emptyHash);
        assertTrue("Hash document should contain the computed CVE hash", source.contains(expectedHash));
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

        // PIT should still be deleted despite the exception
        verify(this.client).execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));

        // Index should NOT have been called since the exception happened before indexing
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Tests that getContext returns the expected CVE context. */
    public void testGetContextReturnsExpectedValue() {
        assertEquals(PluginSettings.getInstance().getCveContext(), this.service.getContext());
    }

    /** Tests that getConsumer returns the expected CVE consumer. */
    public void testGetConsumerReturnsExpectedValue() {
        assertEquals(PluginSettings.getInstance().getCveConsumer(), this.service.getConsumer());
    }

    /** Tests that getMappings returns the CVE mappings. */
    public void testGetMappingsReturnsExpectedMappings() {
        Map<String, String> mappings = this.service.getMappings();

        assertNotNull(mappings);
        assertEquals(1, mappings.size());
        assertEquals("/mappings/cti-cve-mappings.json", mappings.get(Constants.KEY_CVES));
    }

    /** Tests that getAliases returns an empty map. */
    public void testGetAliasesReturnsEmpty() {
        Map<String, String> aliases = this.service.getAliases();

        assertNotNull(aliases);
        assertTrue(aliases.isEmpty());
    }

    /** Tests that when no documents exist, a hash of empty string is stored. */
    @SuppressWarnings("unchecked")
    public void testEmptyIndexProducesEmptyHash() throws Exception {
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
        assertTrue("Document should have hash wrapper", root.has(Constants.KEY_HASH));

        // Hash of empty string should be stored
        String expectedEmptyHash = Resource.computeSha256("");
        String actualHash = root.get(Constants.KEY_HASH).get(Constants.KEY_SHA256).asText();
        assertEquals("Empty index should produce hash of empty string", expectedEmptyHash, actualHash);
    }

    /** Tests hash computation with multiple pages of documents. */
    @SuppressWarnings("unchecked")
    public void testHashComputationWithMultiplePages() {
        this.mockPitLifecycle();

        // First page
        SearchHit hit1 = this.createCveHit(1, "CVE-2024-0001", "hash1");
        SearchHit hit2 = this.createCveHit(2, "CVE-2024-0002", "hash2");
        SearchHits page1Hits =
                new SearchHits(
                        new SearchHit[] {hit1, hit2}, new TotalHits(4, TotalHits.Relation.EQUAL_TO), 1.0f);
        SearchResponse page1Response = mock(SearchResponse.class);
        when(page1Response.getHits()).thenReturn(page1Hits);

        // Second page
        SearchHit hit3 = this.createCveHit(3, "CVE-2024-0003", "hash3");
        SearchHit hit4 = this.createCveHit(4, "CVE-2024-0004", "hash4");
        SearchHits page2Hits =
                new SearchHits(
                        new SearchHit[] {hit3, hit4}, new TotalHits(4, TotalHits.Relation.EQUAL_TO), 1.0f);
        SearchResponse page2Response = mock(SearchResponse.class);
        when(page2Response.getHits()).thenReturn(page2Hits);

        // Empty page to signal end
        SearchResponse emptyResponse = mock(SearchResponse.class);
        when(emptyResponse.getHits()).thenReturn(SearchHits.empty());

        ActionFuture<SearchResponse> page1Future = mock(ActionFuture.class);
        when(page1Future.actionGet()).thenReturn(page1Response);
        ActionFuture<SearchResponse> page2Future = mock(ActionFuture.class);
        when(page2Future.actionGet()).thenReturn(page2Response);
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptyResponse);

        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(page1Future)
                .thenReturn(page2Future)
                .thenReturn(emptyFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        // Verify hash was computed from all four documents
        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        // Expected hash is sha256 of "hash1hash2hash3hash4"
        String expectedHash = Resource.computeSha256("hash1hash2hash3hash4");
        assertTrue(
                "Hash document should contain hash computed from all pages", source.contains(expectedHash));
    }
}
