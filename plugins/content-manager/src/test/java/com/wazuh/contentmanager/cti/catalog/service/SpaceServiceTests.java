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
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.PlainActionFuture;
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
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link SpaceService} class. This test suite verifies the calculation and
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
    @Mock private IndicesExistsResponse indicesExistsResponse;
    @Mock private SearchResponse searchResponse;

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
    @SuppressWarnings("unchecked")
    public void testCalculateAndUpdateSkipsWhenPolicyIndexDoesNotExist() {
        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        doAnswer(
                        invocation -> {
                            ActionListener<IndicesExistsResponse> listener = invocation.getArgument(1);
                            listener.onResponse(this.indicesExistsResponse);
                            return null;
                        })
                .when(this.indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any());
        when(this.indicesExistsResponse.isExists()).thenReturn(false);

        PlainActionFuture<Set<String>> future = new PlainActionFuture<>();
        this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()), future);
        future.actionGet();

        verify(this.client, never()).search(any(SearchRequest.class), any());
    }

    /**
     * Tests that calculateAndUpdate handles empty policy search results without performing bulk
     * updates.
     */
    @SuppressWarnings("unchecked")
    public void testCalculateAndUpdateHandlesEmptyPolicies() {
        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        doAnswer(
                        invocation -> {
                            ActionListener<IndicesExistsResponse> listener = invocation.getArgument(1);
                            listener.onResponse(this.indicesExistsResponse);
                            return null;
                        })
                .when(this.indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any());
        when(this.indicesExistsResponse.isExists()).thenReturn(true);

        doAnswer(
                        invocation -> {
                            ActionListener<SearchResponse> listener = invocation.getArgument(1);
                            listener.onResponse(this.searchResponse);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any());
        SearchHits emptyHits = SearchHits.empty();
        when(this.searchResponse.getHits()).thenReturn(emptyHits);

        PlainActionFuture<Set<String>> future = new PlainActionFuture<>();
        this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()), future);
        future.actionGet();

        verify(this.client).search(any(SearchRequest.class), any());
        verify(this.client, never()).bulk(any(), any());
    }

    /** Tests that calculateAndUpdate handles exceptions gracefully without propagating them. */
    public void testCalculateAndUpdateHandlesException() {
        when(this.client.admin()).thenThrow(new RuntimeException("Test exception"));

        PlainActionFuture<Set<String>> future = new PlainActionFuture<>();
        this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()), future);
        future.actionGet();
    }

    /**
     * Tests that initializeSpace sets enabled=true only for the draft space and enabled=false for
     * other spaces (test, custom, standard).
     */
    @SuppressWarnings("unchecked")
    public void testInitializeSpace_DraftPolicyEnabledTrue() {
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(1);
                            listener.onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any());

        PlainActionFuture<Void> future = new PlainActionFuture<>();
        this.policyHashService.initializeSpace("draft", "test-doc-id", future);
        future.actionGet();

        verify(this.client).index(captor.capture(), any());
        IndexRequest request = captor.getValue();
        String sourceJson = request.source().utf8ToString();
        assertTrue(
                "Draft policy should contain enabled: true", sourceJson.contains("\"enabled\":true"));
    }

    /**
     * Tests that initializeSpace sets enabled=false for non-draft spaces (test, custom, standard).
     */
    @SuppressWarnings("unchecked")
    public void testInitializeSpace_NonDraftPoliciesEnabledFalse() {
        for (String spaceName : new String[] {"test", "custom", "standard"}) {
            Mockito.reset(this.client);

            ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
            doAnswer(
                            invocation -> {
                                ActionListener<IndexResponse> listener = invocation.getArgument(1);
                                listener.onResponse(mock(IndexResponse.class));
                                return null;
                            })
                    .when(this.client)
                    .index(any(IndexRequest.class), any());

            PlainActionFuture<Void> future = new PlainActionFuture<>();
            this.policyHashService.initializeSpace(spaceName, "test-doc-id", future);
            future.actionGet();

            verify(this.client).index(captor.capture(), any());
            IndexRequest request = captor.getValue();
            String sourceJson = request.source().utf8ToString();
            assertTrue(
                    "Policy for space '" + spaceName + "' should contain enabled: false",
                    sourceJson.contains("\"enabled\":false"));
        }
    }
}
