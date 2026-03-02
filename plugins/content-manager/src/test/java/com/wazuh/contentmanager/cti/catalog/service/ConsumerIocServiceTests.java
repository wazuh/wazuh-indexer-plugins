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
import org.opensearch.search.aggregations.Aggregations;
import org.opensearch.search.aggregations.bucket.terms.Terms;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.util.Collections;
import java.util.List;
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

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);
        this.service = new ConsumerIocService(this.client, this.consumersIndex, this.environment);
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
     * Creates a mock SearchResponse that returns the given types in a terms aggregation and empty
     * hits.
     */
    @SuppressWarnings("unchecked")
    private SearchResponse mockAggregationResponse(List<String> types) {
        Terms termsAgg = mock(Terms.class);
        when(termsAgg.getName()).thenReturn("ioc_types");
        List<Terms.Bucket> buckets =
                types.stream()
                        .map(
                                type -> {
                                    Terms.Bucket bucket = mock(Terms.Bucket.class);
                                    when(bucket.getKeyAsString()).thenReturn(type);
                                    return bucket;
                                })
                        .collect(java.util.stream.Collectors.toList());
        when(termsAgg.getBuckets()).thenReturn((List) buckets);

        Aggregations aggregations = new Aggregations(List.of(termsAgg));

        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits()).thenReturn(SearchHits.empty());
        when(response.getAggregations()).thenReturn(aggregations);
        return response;
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

        // First search returns aggregation with two types; subsequent searches return empty hits
        SearchResponse aggResponse = this.mockAggregationResponse(List.of("connection", "url-full"));
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> aggFuture = mock(ActionFuture.class);
        when(aggFuture.actionGet()).thenReturn(aggResponse);
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(aggFuture) // aggregation query
                .thenReturn(emptyFuture) // connection hash (empty)
                .thenReturn(emptyFuture); // url-full hash (empty)

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        // Verify PIT was created and deleted
        verify(this.client).execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
        verify(this.client).execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));

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

        List<String> discoveredTypes = List.of("connection", "url-full", "hash_md5");

        SearchResponse aggResponse = this.mockAggregationResponse(discoveredTypes);
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());
        ActionFuture<SearchResponse> aggFuture = mock(ActionFuture.class);
        when(aggFuture.actionGet()).thenReturn(aggResponse);
        ActionFuture<SearchResponse> emptyFuture = mock(ActionFuture.class);
        when(emptyFuture.actionGet()).thenReturn(emptySearchResponse);
        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(aggFuture)
                .thenReturn(emptyFuture)
                .thenReturn(emptyFuture)
                .thenReturn(emptyFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        JsonNode root = MAPPER.readTree(source);
        assertTrue("Document should have type_hashes wrapper", root.has(Constants.KEY_TYPE_HASHES));
        JsonNode typeHashes = root.get(Constants.KEY_TYPE_HASHES);

        for (String type : discoveredTypes) {
            assertTrue("type_hashes should contain type '" + type + "'", typeHashes.has(type));
            assertTrue(
                    "Type '" + type + "' should have hash.sha256",
                    typeHashes.path(type).path(Constants.KEY_HASH).has(Constants.KEY_SHA256));
        }

        // All types should have the SHA-256 of empty string (no documents matched)
        String emptyHash = Resource.computeSha256("");
        for (String type : discoveredTypes) {
            assertEquals(
                    "Hash for type '" + type + "' should be SHA-256 of empty string",
                    emptyHash,
                    typeHashes.path(type).path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText());
        }
    }

    /** Tests hash computation with actual IOC documents. */
    @SuppressWarnings("unchecked")
    public void testHashComputationWithDocuments() {
        this.mockPitLifecycle();

        // Build a search response with one hit for the "connection" type
        String connDocHash = "abc123def456";
        String connDocSource =
                "{\"document\":{\"type\":\"connection\",\"name\":\"test-ioc\"},"
                        + "\"hash\":{\"sha256\":\""
                        + connDocHash
                        + "\"}}";
        SearchHit connHit = new SearchHit(1, "doc-1", Collections.emptyMap(), Collections.emptyMap());
        connHit.sourceRef(new org.opensearch.core.common.bytes.BytesArray(connDocSource));
        connHit.sortValues(
                new Object[] {"doc-1"}, new org.opensearch.search.DocValueFormat[] {DocValueFormat.RAW});
        SearchHits connHits =
                new SearchHits(
                        new SearchHit[] {connHit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);

        // Aggregation discovers only "connection"
        SearchResponse aggResponse = this.mockAggregationResponse(List.of("connection"));
        SearchResponse connSearchResponse = mock(SearchResponse.class);
        when(connSearchResponse.getHits()).thenReturn(connHits);
        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());

        ActionFuture<SearchResponse> aggFuture = mock(ActionFuture.class);
        when(aggFuture.actionGet()).thenReturn(aggResponse);
        ActionFuture<SearchResponse> connSearchFuture = mock(ActionFuture.class);
        when(connSearchFuture.actionGet()).thenReturn(connSearchResponse);
        ActionFuture<SearchResponse> emptySearchFuture = mock(ActionFuture.class);
        when(emptySearchFuture.actionGet()).thenReturn(emptySearchResponse);

        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(aggFuture) // aggregation
                .thenReturn(connSearchFuture) // connection page 1
                .thenReturn(emptySearchFuture); // connection page 2 (empty = done)

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

        // PIT should still be deleted despite the exception
        verify(this.client).execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class));

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

    /** Tests that when no types are discovered, an empty type_hashes document is stored. */
    @SuppressWarnings("unchecked")
    public void testEmptyIndexProducesEmptyTypeHashes() throws Exception {
        this.mockPitLifecycle();

        // Aggregation discovers no types
        SearchResponse aggResponse = this.mockAggregationResponse(List.of());
        ActionFuture<SearchResponse> aggFuture = mock(ActionFuture.class);
        when(aggFuture.actionGet()).thenReturn(aggResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(aggFuture);

        this.mockIndexResponse();

        this.service.onSyncComplete(true);

        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        JsonNode root = MAPPER.readTree(source);
        assertTrue("Document should have type_hashes wrapper", root.has(Constants.KEY_TYPE_HASHES));
        assertEquals(
                "type_hashes should be empty when no types are discovered",
                0,
                root.get(Constants.KEY_TYPE_HASHES).size());
    }
}
