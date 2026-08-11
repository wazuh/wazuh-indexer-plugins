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
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequestBuilder;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link PolicyHashService} class. This test suite verifies the calculation and
 * update of aggregate policy hashes based on their associated integrations, rules, decoders, and
 * key-value databases.
 *
 * <p>Tests cover scenarios including proper handling of missing indices, hash calculation for
 * policies with multiple integrations, and correct aggregation of hashes from related resources.
 * Mock objects simulate OpenSearch client interactions to test hash computation logic in isolation.
 */
public class SpaceServiceTests extends OpenSearchTestCase {

    private SpaceService policyHashService;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private AdminClient adminClient;
    @Mock private IndicesAdminClient indicesAdminClient;
    @Mock private IndicesExistsRequestBuilder indicesExistsRequestBuilder;
    @Mock private IndicesExistsResponse indicesExistsResponse;
    @Mock private ActionFuture<SearchResponse> searchFuture;
    @Mock private SearchResponse searchResponse;

    private static final String POLICY_IDX = "wazuh-threatintel-policies";
    private static final String INTEGRATION_IDX = "wazuh-threatintel-integrations";
    private static final String DECODER_IDX = "wazuh-threatintel-decoders";
    private static final String KVDB_IDX = "wazuh-threatintel-kvdbs";
    private static final String RULE_IDX = "wazuh-threatintel-rules";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(Settings.EMPTY);
        this.closeable = MockitoAnnotations.openMocks(this);
        this.policyHashService = new SpaceService(this.client);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Tests that calculateAndUpdate skips execution when the policy index does not exist. */
    public void testCalculateAndUpdateSkipsWhenPolicyIndexDoesNotExist() {
        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        when(this.indicesExistsResponse.isExists()).thenReturn(false);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<IndicesExistsResponse>>getArgument(1)
                                    .onResponse(this.indicesExistsResponse);
                            return null;
                        })
                .when(this.indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any());

        this.policyHashService.calculateAndUpdate(
                List.of(Space.DRAFT.toString()), ActionListener.wrap(r -> {}, e -> {}));

        verify(this.client, never()).search(any(SearchRequest.class), any());
    }

    /**
     * Tests that calculateAndUpdate handles empty policy search results without performing bulk
     * updates.
     */
    public void testCalculateAndUpdateHandlesEmptyPolicies() {
        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        when(this.indicesExistsResponse.isExists()).thenReturn(true);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<IndicesExistsResponse>>getArgument(1)
                                    .onResponse(this.indicesExistsResponse);
                            return null;
                        })
                .when(this.indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any());

        SearchHits emptyHits = SearchHits.empty();
        when(this.searchResponse.getHits()).thenReturn(emptyHits);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<SearchResponse>>getArgument(1)
                                    .onResponse(this.searchResponse);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any());

        // Should not throw any exception
        this.policyHashService.calculateAndUpdate(
                List.of(Space.DRAFT.toString()), ActionListener.wrap(r -> {}, e -> {}));

        verify(this.client).search(any(SearchRequest.class), any());
        // No bulk update should be performed when there are no policies
        verify(this.client, never()).bulk(any(), any());
    }

    /** Tests that calculateAndUpdate handles exceptions gracefully without propagating them. */
    public void testCalculateAndUpdateHandlesException() {
        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<IndicesExistsResponse>>getArgument(1)
                                    .onFailure(new RuntimeException("Test exception"));
                            return null;
                        })
                .when(this.indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any());

        AtomicReference<Boolean> gotResponse = new AtomicReference<>(false);
        // Should not propagate the exception - it should be handled and reported as an empty result.
        this.policyHashService.calculateAndUpdate(
                List.of(Space.DRAFT.toString()),
                ActionListener.wrap(r -> gotResponse.set(true), e -> gotResponse.set(false)));

        assertTrue("Failure should be handled gracefully via onResponse", gotResponse.get());
    }

    /** Tests that initializeSpace sets enabled=true for the draft space. */
    public void testInitializeSpace_DraftPolicyEnabledTrue() {
        // Arrange
        org.mockito.ArgumentCaptor<IndexRequest> captor =
                org.mockito.ArgumentCaptor.forClass(IndexRequest.class);
        IndexResponse mockResponse = org.mockito.Mockito.mock(IndexResponse.class);
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<IndexResponse>>getArgument(1).onResponse(mockResponse);
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any());

        // Act: Initialize draft space
        this.policyHashService.initializeSpace(
                "draft", "test-doc-id", ActionListener.wrap(r -> {}, e -> {}));

        // Verify the IndexRequest contains enabled=true for draft space
        verify(this.client).index(captor.capture(), any());
        IndexRequest request = captor.getValue();
        String sourceJson = request.source().utf8ToString();
        assertTrue(
                "Draft policy should contain enabled: true", sourceJson.contains("\"enabled\":true"));
    }

    /**
     * Tests that initializeSpace also sets enabled=true for non-draft spaces (test, custom,
     * standard), matching the draft space so the promote preview does not surface the "enabled"
     * mismatch as a false unpromoted change on a fresh installation.
     */
    public void testInitializeSpace_NonDraftPoliciesEnabledTrue() {
        // Test for all non-draft spaces
        for (String spaceName : new String[] {"test", "custom", "standard"}) {
            // Reinitialize mocks for each space
            org.mockito.Mockito.reset(this.client);

            org.mockito.ArgumentCaptor<IndexRequest> captor =
                    org.mockito.ArgumentCaptor.forClass(IndexRequest.class);
            IndexResponse mockResponse = org.mockito.Mockito.mock(IndexResponse.class);
            doAnswer(
                            invocation -> {
                                invocation.<ActionListener<IndexResponse>>getArgument(1).onResponse(mockResponse);
                                return null;
                            })
                    .when(this.client)
                    .index(any(IndexRequest.class), any());

            // Act: Initialize non-draft space
            this.policyHashService.initializeSpace(
                    spaceName, "test-doc-id", ActionListener.wrap(r -> {}, e -> {}));

            // Verify the IndexRequest contains enabled=true for non-draft spaces too
            verify(this.client).index(captor.capture(), any());
            IndexRequest request = captor.getValue();
            String sourceJson = request.source().utf8ToString();
            assertTrue(
                    "Policy for space '" + spaceName + "' should contain enabled: true",
                    sourceJson.contains("\"enabled\":true"));
        }
    }

    /**
     * Tests that recalculateSpaceHashIfMissing does nothing when the space has no policy document
     * yet, which is the state of a fresh cluster before the catalog has been synchronized.
     */
    public void testRecalculateSpaceHashIfMissingSkipsWhenPolicyIsAbsent() {
        mockPolicySearch(emptySearchResponse());

        AtomicReference<Set<String>> changed = new AtomicReference<>(null);
        this.policyHashService.recalculateSpaceHashIfMissing(
                Space.STANDARD.toString(), ActionListener.wrap(changed::set, e -> {}));

        assertNotNull("Listener should have been notified", changed.get());
        assertTrue("No space should be reported as changed", changed.get().isEmpty());
        verify(this.client, never()).admin();
        verify(this.client, never()).bulk(any(), any());
    }

    /** Tests that recalculateSpaceHashIfMissing leaves an already-calculated hash untouched. */
    public void testRecalculateSpaceHashIfMissingSkipsWhenHashIsPresent() {
        mockPolicySearch(
                searchResponse(
                        policyHit(
                                "{\"space\":{\"name\":\"standard\",\"hash\":{\"sha256\":\"abc123\"}},\"hash\":{\"sha256\":\"doc-hash\"}}")));

        AtomicReference<Set<String>> changed = new AtomicReference<>(null);
        this.policyHashService.recalculateSpaceHashIfMissing(
                Space.STANDARD.toString(), ActionListener.wrap(changed::set, e -> {}));

        assertNotNull("Listener should have been notified", changed.get());
        assertTrue("No space should be reported as changed", changed.get().isEmpty());
        verify(this.client, never()).admin();
        verify(this.client, never()).bulk(any(), any());
    }

    /**
     * Tests the recovery path: a policy whose aggregate hash was never persisted (a hash calculation
     * interrupted by a node restart) is recalculated, the resulting update carries a
     * space.hash.sha256, and the space is reported as changed so callers can trigger an Engine
     * reload.
     */
    public void testRecalculateSpaceHashIfMissingRecalculatesWhenHashIsAbsent() {
        SearchResponse policyResponse =
                searchResponse(
                        policyHit("{\"space\":{\"name\":\"standard\"},\"hash\":{\"sha256\":\"doc-hash\"}}"));
        // Both the hash check and the recalculation read the policies index.
        mockPolicySearch(policyResponse);
        mockPolicyIndexExists(true);

        org.mockito.ArgumentCaptor<BulkRequest> bulkCaptor =
                org.mockito.ArgumentCaptor.forClass(BulkRequest.class);
        BulkResponse bulkResponse = org.mockito.Mockito.mock(BulkResponse.class);
        when(bulkResponse.hasFailures()).thenReturn(false);
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<BulkResponse>>getArgument(1).onResponse(bulkResponse);
                            return null;
                        })
                .when(this.client)
                .bulk(any(BulkRequest.class), any());

        AtomicReference<Set<String>> changed = new AtomicReference<>(null);
        this.policyHashService.recalculateSpaceHashIfMissing(
                Space.STANDARD.toString(), ActionListener.wrap(changed::set, e -> {}));

        assertNotNull("Listener should have been notified", changed.get());
        assertEquals(
                "The standard space should be reported as changed",
                Set.of(Space.STANDARD.toString()),
                changed.get());

        verify(this.client).bulk(bulkCaptor.capture(), any());
        UpdateRequest update = (UpdateRequest) bulkCaptor.getValue().requests().get(0);
        String updateJson = update.doc().source().utf8ToString();
        assertTrue(
                "The recalculated update should carry an aggregate hash, was: " + updateJson,
                updateJson.contains("\"sha256\":\""));
        assertEquals(POLICY_IDX, update.index());
    }

    /**
     * Tests that an unreadable policies index (an expected pre-initialization state at startup)
     * propagates the failure to the caller so it can decide whether to retry.
     */
    public void testRecalculateSpaceHashIfMissingPropagatesFailure() {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<SearchResponse>>getArgument(1)
                                    .onFailure(new RuntimeException("no such index"));
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any());

        AtomicReference<Set<String>> changed = new AtomicReference<>(null);
        AtomicReference<Exception> failure = new AtomicReference<>(null);
        this.policyHashService.recalculateSpaceHashIfMissing(
                Space.STANDARD.toString(), ActionListener.wrap(changed::set, failure::set));

        assertNotNull("Failure should be propagated via onFailure", failure.get());
        assertNull("onResponse should not have been called", changed.get());
    }

    private SearchHit policyHit(String sourceJson) {
        SearchHit hit =
                new SearchHit(1, "standard-policy-id", Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(new BytesArray(sourceJson.getBytes(StandardCharsets.UTF_8)));
        return hit;
    }

    private SearchResponse searchResponse(SearchHit... hits) {
        SearchResponse response = org.mockito.Mockito.mock(SearchResponse.class);
        when(response.getHits())
                .thenReturn(
                        new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f));
        return response;
    }

    private SearchResponse emptySearchResponse() {
        return searchResponse(new SearchHit[0]);
    }

    private void mockPolicySearch(SearchResponse response) {
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<SearchResponse>>getArgument(1).onResponse(response);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any());
    }

    private void mockPolicyIndexExists(boolean exists) {
        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        when(this.indicesExistsResponse.isExists()).thenReturn(exists);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<IndicesExistsResponse>>getArgument(1)
                                    .onResponse(this.indicesExistsResponse);
                            return null;
                        })
                .when(this.indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any());
    }
}
