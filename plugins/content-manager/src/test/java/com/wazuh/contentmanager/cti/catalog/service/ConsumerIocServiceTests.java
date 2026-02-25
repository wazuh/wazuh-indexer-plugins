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
        when(this.environment.tmpDir()).thenReturn(createTempDir());
        when(this.engineService.loadIocs(anyString())).thenReturn(new RestResponse("OK", 200));
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

    /** Tests that onSyncComplete does nothing when isUpdated is false. */
    public void testOnSyncCompleteSkipsWhenNotUpdated() {
        this.service.onSyncComplete(false);

        verify(this.client, never()).execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class));
    }

    /** Tests that onSyncComplete computes and stores hashes when isUpdated is true. */
    @SuppressWarnings("unchecked")
    public void testOnSyncCompleteComputesHashesWhenUpdated() {
        // Mock PIT creation
        CreatePitResponse pitResponse = mock(CreatePitResponse.class);
        when(pitResponse.getId()).thenReturn("test-pit-id");
        ActionFuture<CreatePitResponse> pitFuture = mock(ActionFuture.class);
        when(pitFuture.actionGet()).thenReturn(pitResponse);
        when(this.client.execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class)))
                .thenReturn(pitFuture);

        // Mock search returning empty results for all types (no IOC documents)
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

    /** Tests that the hash document contains all expected IOC types. */
    @SuppressWarnings("unchecked")
    public void testHashDocumentContainsAllIocTypes() {
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

        // Capture the indexed document and verify all IOC types are present
        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        for (String type : Constants.IOC_TYPES) {
            assertTrue(
                    "Hash document should contain type '" + type + "'", source.contains("\"" + type + "\""));
        }

        // All types should have the SHA-256 of empty string (no documents matched)
        String emptyHash = Resource.computeSha256("");
        for (String type : Constants.IOC_TYPES) {
            assertTrue(
                    "Hash for type '" + type + "' should be SHA-256 of empty string",
                    source.contains(emptyHash));
        }
    }

    /** Tests hash computation with actual IOC documents. */
    @SuppressWarnings("unchecked")
    public void testHashComputationWithDocuments() {
        // Mock PIT creation
        CreatePitResponse pitResponse = mock(CreatePitResponse.class);
        when(pitResponse.getId()).thenReturn("test-pit-id");
        ActionFuture<CreatePitResponse> pitFuture = mock(ActionFuture.class);
        when(pitFuture.actionGet()).thenReturn(pitResponse);
        when(this.client.execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class)))
                .thenReturn(pitFuture);

        // Build a search response with one hit for "ip" type, empty for the rest
        String ipDocHash = "abc123def456";
        String ipDocSource =
                "{\"document\":{\"type\":\"ipv4-addr\",\"name\":\"test-ioc\"},"
                        + "\"hash\":{\"sha256\":\""
                        + ipDocHash
                        + "\"}}";
        SearchHit ipHit = new SearchHit(1, "doc-1", Collections.emptyMap(), Collections.emptyMap());
        ipHit.sourceRef(new org.opensearch.core.common.bytes.BytesArray(ipDocSource));
        ipHit.sortValues(
                new Object[] {"doc-1"}, new org.opensearch.search.DocValueFormat[] {DocValueFormat.RAW});
        SearchHits ipHits =
                new SearchHits(
                        new SearchHit[] {ipHit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);

        // First call for "ip" type returns the hit, second call returns empty (pagination end)
        // All other types return empty immediately
        SearchResponse ipSearchResponse = mock(SearchResponse.class);
        when(ipSearchResponse.getHits()).thenReturn(ipHits);

        SearchResponse emptySearchResponse = mock(SearchResponse.class);
        when(emptySearchResponse.getHits()).thenReturn(SearchHits.empty());

        ActionFuture<SearchResponse> ipSearchFuture = mock(ActionFuture.class);
        when(ipSearchFuture.actionGet()).thenReturn(ipSearchResponse);

        ActionFuture<SearchResponse> emptySearchFuture = mock(ActionFuture.class);
        when(emptySearchFuture.actionGet()).thenReturn(emptySearchResponse);

        // ip: first call returns hit, second returns empty. All others return empty.
        when(this.client.search(any(SearchRequest.class)))
                .thenReturn(ipSearchFuture) // ip page 1
                .thenReturn(emptySearchFuture) // ip page 2 (empty = done)
                .thenReturn(emptySearchFuture) // domain-name
                .thenReturn(emptySearchFuture) // url
                .thenReturn(emptySearchFuture) // file
                .thenReturn(emptySearchFuture); // geo

        // Mock index response
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenReturn(mock(IndexResponse.class));
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Mock PIT deletion
        ActionFuture<?> deletePitFuture = mock(ActionFuture.class);
        when(this.client.execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class)))
                .thenReturn((ActionFuture) deletePitFuture);

        this.service.onSyncComplete(true);

        // Verify the hash for "ip" type differs from the empty hash
        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(indexCaptor.capture());
        String source = indexCaptor.getValue().source().utf8ToString();

        String expectedIpHash = Resource.computeSha256(ipDocHash);
        String emptyHash = Resource.computeSha256("");
        assertNotEquals("ip hash should differ from empty hash", expectedIpHash, emptyHash);
        assertTrue(
                "Hash document should contain the computed ip hash", source.contains(expectedIpHash));
    }

    /** Tests that the PIT is deleted even when an exception occurs during hash computation. */
    @SuppressWarnings("unchecked")
    public void testPitDeletedOnException() {
        // Mock PIT creation
        CreatePitResponse pitResponse = mock(CreatePitResponse.class);
        when(pitResponse.getId()).thenReturn("test-pit-id");
        ActionFuture<CreatePitResponse> pitFuture = mock(ActionFuture.class);
        when(pitFuture.actionGet()).thenReturn(pitResponse);
        when(this.client.execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class)))
                .thenReturn(pitFuture);

        // Mock search to throw an exception
        when(this.client.search(any(SearchRequest.class)))
                .thenThrow(new RuntimeException("Search failed"));

        // Mock PIT deletion
        ActionFuture<?> deletePitFuture = mock(ActionFuture.class);
        when(this.client.execute(eq(DeletePitAction.INSTANCE), any(DeletePitRequest.class)))
                .thenReturn((ActionFuture) deletePitFuture);

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

        verify(this.engineService).loadIocs(anyString());
    }

    /** Tests that onSyncComplete(false) does not call engineService.loadIocs. */
    public void testOnSyncCompleteDoesNotNotifyEngineWhenNotUpdated() {
        this.service.onSyncComplete(false);

        verify(this.engineService, never()).loadIocs(anyString());
    }

    /** Tests that engine notification failure does not propagate as an exception. */
    @SuppressWarnings("unchecked")
    public void testEngineNotificationFailureDoesNotPropagate() {
        // Override the engineService mock to return an error
        when(this.engineService.loadIocs(anyString()))
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

        verify(this.engineService).loadIocs(anyString());
    }

    /** Tests that search is paginated — one search per type (all empty) plus no extra. */
    @SuppressWarnings("unchecked")
    public void testSearchPerformedForEachType() {
        // Mock PIT creation
        CreatePitResponse pitResponse = mock(CreatePitResponse.class);
        when(pitResponse.getId()).thenReturn("test-pit-id");
        ActionFuture<CreatePitResponse> pitFuture = mock(ActionFuture.class);
        when(pitFuture.actionGet()).thenReturn(pitResponse);
        when(this.client.execute(eq(CreatePitAction.INSTANCE), any(CreatePitRequest.class)))
                .thenReturn(pitFuture);

        // Mock search returning empty results for all types
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

        // One search per IOC type for hash computation + one search for NDJSON export (empty = done)
        verify(this.client, times(Constants.IOC_TYPES.size() + 1)).search(any(SearchRequest.class));
    }
}
