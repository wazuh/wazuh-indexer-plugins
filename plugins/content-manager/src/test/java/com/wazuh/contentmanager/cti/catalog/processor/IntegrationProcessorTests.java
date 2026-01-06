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
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.List;
import java.util.Map;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Tests for the IntegrationProcessor class. */
public class IntegrationProcessorTests extends OpenSearchTestCase {

    private IntegrationProcessor integrationProcessor;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private AdminClient adminClient;
    @Mock private IndicesAdminClient indicesAdminClient;
    @Mock private IndicesExistsRequestBuilder indicesExistsRequestBuilder;
    @Mock private IndicesExistsResponse indicesExistsResponse;
    @Mock private ActionFuture<SearchResponse> searchFuture;
    @Mock private SearchResponse searchResponse;
    @Mock private SearchHits searchHits;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.integrationProcessor = new IntegrationProcessor(client);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    public void testProcessReturnsEmptyMapWhenIndexDoesNotExist() {
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(indicesAdminClient.prepareExists(anyString())).thenReturn(indicesExistsRequestBuilder);
        when(indicesExistsRequestBuilder.get()).thenReturn(indicesExistsResponse);
        when(indicesExistsResponse.isExists()).thenReturn(false);

        Map<String, List<String>> result = integrationProcessor.process("non-existent-index");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.isEmpty());
        verify(client, never()).search(any(SearchRequest.class));
    }

    public void testProcessReturnsEmptyMapWhenNoDocuments() {
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(indicesAdminClient.prepareExists(anyString())).thenReturn(indicesExistsRequestBuilder);
        when(indicesExistsRequestBuilder.get()).thenReturn(indicesExistsResponse);
        when(indicesExistsResponse.isExists()).thenReturn(true);

        when(client.search(any(SearchRequest.class))).thenReturn(searchFuture);
        when(searchFuture.actionGet()).thenReturn(searchResponse);
        when(searchResponse.getHits()).thenReturn(searchHits);
        when(searchHits.getHits()).thenReturn(new SearchHit[0]);

        Map<String, List<String>> result = integrationProcessor.process("test-index");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.isEmpty());
    }
}
