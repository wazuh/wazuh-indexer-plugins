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
package com.wazuh.contentmanager.cti.catalog.service;

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequestBuilder;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Before;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Tests for the PolicyHashService class. */
public class PolicyHashServiceTests extends OpenSearchTestCase {

    private PolicyHashService policyHashService;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private AdminClient adminClient;
    @Mock private IndicesAdminClient indicesAdminClient;
    @Mock private IndicesExistsRequestBuilder indicesExistsRequestBuilder;
    @Mock private IndicesExistsResponse indicesExistsResponse;
    @Mock private ActionFuture<SearchResponse> searchFuture;
    @Mock private SearchResponse searchResponse;

    private static final String CONTEXT = "decoders_development_0.0.1";
    private static final String CONSUMER = "decoders_development_0.0.1";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.policyHashService = new PolicyHashService(client);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    public void testCalculateAndUpdateSkipsWhenPolicyIndexDoesNotExist() {
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(indicesAdminClient.prepareExists(anyString())).thenReturn(indicesExistsRequestBuilder);
        when(indicesExistsRequestBuilder.get()).thenReturn(indicesExistsResponse);
        when(indicesExistsResponse.isExists()).thenReturn(false);

        policyHashService.calculateAndUpdate(CONTEXT, CONSUMER);

        verify(client, never()).search(any(SearchRequest.class));
    }

    public void testCalculateAndUpdateHandlesEmptyPolicies() {
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(indicesAdminClient.prepareExists(anyString())).thenReturn(indicesExistsRequestBuilder);
        when(indicesExistsRequestBuilder.get()).thenReturn(indicesExistsResponse);
        when(indicesExistsResponse.isExists()).thenReturn(true);

        when(client.search(any(SearchRequest.class))).thenReturn(searchFuture);
        when(searchFuture.actionGet()).thenReturn(searchResponse);
        SearchHits emptyHits = SearchHits.empty();
        when(searchResponse.getHits()).thenReturn(emptyHits);

        // Should not throw any exception
        policyHashService.calculateAndUpdate(CONTEXT, CONSUMER);

        verify(client).search(any(SearchRequest.class));
        // No bulk update should be performed when there are no policies
        verify(client, never()).bulk(any());
    }

    public void testCalculateAndUpdateHandlesException() {
        when(client.admin()).thenThrow(new RuntimeException("Test exception"));

        // Should not throw any exception - it should be caught internally
        policyHashService.calculateAndUpdate(CONTEXT, CONSUMER);
    }
}
