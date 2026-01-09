/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.processor;

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequestBuilder;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Before;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Tests for the DetectorProcessor class. */
public class DetectorProcessorTests extends OpenSearchTestCase {

    private DetectorProcessor detectorProcessor;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private AdminClient adminClient;
    @Mock private IndicesAdminClient indicesAdminClient;
    @Mock private IndicesExistsRequestBuilder indicesExistsRequestBuilder;
    @Mock private IndicesExistsResponse indicesExistsResponse;
    @Mock private ActionFuture<SearchResponse> searchFuture;
    @Mock private SearchResponse searchResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);
        this.detectorProcessor = new DetectorProcessor(this.client);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Tests that process skips execution when the integration index does not exist. */
    public void testProcessSkipsWhenIndexDoesNotExist() {
        Map<String, List<String>> integrations = new HashMap<>();
        integrations.put("test-integration", List.of("rule-1", "rule-2"));

        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        when(this.indicesAdminClient.prepareExists(anyString()))
                .thenReturn(this.indicesExistsRequestBuilder);
        when(this.indicesExistsRequestBuilder.get()).thenReturn(this.indicesExistsResponse);
        when(this.indicesExistsResponse.isExists()).thenReturn(false);
        this.detectorProcessor.process(integrations, "non-existent-index");

        verify(this.client, never()).search(any(SearchRequest.class));
    }

    /** Tests that process handles empty search results without throwing exceptions. */
    public void testProcessHandlesEmptySearchResults() {
        Map<String, List<String>> integrations = new HashMap<>();
        integrations.put("test-integration", List.of("rule-1"));

        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        when(this.indicesAdminClient.prepareExists(anyString()))
                .thenReturn(this.indicesExistsRequestBuilder);
        when(this.indicesExistsRequestBuilder.get()).thenReturn(this.indicesExistsResponse);
        when(this.indicesExistsResponse.isExists()).thenReturn(true);
        when(this.client.search(any(SearchRequest.class))).thenReturn(this.searchFuture);
        when(this.searchFuture.actionGet()).thenReturn(this.searchResponse);
        SearchHits emptyHits = SearchHits.empty();
        when(this.searchResponse.getHits()).thenReturn(emptyHits);
        // Should not throw any exception
        this.detectorProcessor.process(integrations, "test-index");

        verify(this.client).search(any(SearchRequest.class));
    }

    /** Tests that process handles an empty integrations map without throwing exceptions. */
    public void testProcessHandlesEmptyIntegrationsMap() {
        Map<String, List<String>> integrations = new HashMap<>();

        when(this.client.admin()).thenReturn(this.adminClient);
        when(this.adminClient.indices()).thenReturn(this.indicesAdminClient);
        when(this.indicesAdminClient.prepareExists(anyString()))
                .thenReturn(this.indicesExistsRequestBuilder);
        when(this.indicesExistsRequestBuilder.get()).thenReturn(this.indicesExistsResponse);
        when(this.indicesExistsResponse.isExists()).thenReturn(true);
        when(this.client.search(any(SearchRequest.class))).thenReturn(this.searchFuture);
        when(this.searchFuture.actionGet()).thenReturn(this.searchResponse);
        SearchHits emptyHits2 = SearchHits.empty();
        when(this.searchResponse.getHits()).thenReturn(emptyHits2);
        // Should not throw any exception
        this.detectorProcessor.process(integrations, "test-index");
    }
}
