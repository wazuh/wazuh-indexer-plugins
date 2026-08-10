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

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequestBuilder;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Before;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;
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

    /**
     * The policy scan must only pick up actual policies, which are the documents carrying {@code
     * space.name}.
     *
     * <p>The user-overrides registry also lives in the policies index and deliberately has no {@code
     * space.name}. Without this filter it fell through the space check in {@code processHitsAsync} --
     * which only skips a hit when {@code space} is present -- and had a meaningless {@code
     * space.hash} written into it on every recalculation.
     */
    public void testCalculateAndUpdateOnlyScansDocumentsThatAreActuallyPolicies() {
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

        when(this.searchResponse.getHits()).thenReturn(SearchHits.empty());
        ArgumentCaptor<SearchRequest> captor = ArgumentCaptor.forClass(SearchRequest.class);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<SearchResponse>>getArgument(1)
                                    .onResponse(this.searchResponse);
                            return null;
                        })
                .when(this.client)
                .search(captor.capture(), any());

        this.policyHashService.calculateAndUpdate(
                List.of(Space.STANDARD.toString()), ActionListener.wrap(r -> {}, e -> {}));

        String query = captor.getValue().source().query().toString();
        assertTrue(
                "the scan must require space.name, or non-policy documents are processed as policies",
                query.contains(Constants.Q_SPACE_NAME) && query.contains("exists"));
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
}
