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
package com.wazuh.contentmanager.rest.services;

import com.fasterxml.jackson.databind.JsonNode;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestDeleteKvdbAction} class. This test suite validates the REST API
 * endpoint responsible for deleting new CTI Kvdbs.
 *
 * <p>Tests verify Kvdb delete requests, proper handling of Kvdb data, and appropriate HTTP response
 * codes for successful Kvdb delete errors.
 */
public class RestDeleteKvdbActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestDeleteKvdbAction action;

    /** Initialize PluginSettings singleton once for all tests. */
    @BeforeClass
    public static void setUpClass() {
        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
        }
    }

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.service = mock(EngineService.class);
        this.action = new RestDeleteKvdbAction(this.service);
    }

    /**
     * Test the {@link RestDeleteKvdbAction#handleRequest(RestRequest, Client)} method when the request is
     * complete. The expected response is: {201, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteKvdb201() throws IOException {
        // Mock
        RestRequest request = buildRequest(null, "k_82e215c4-988a-4f64-8d15-b98b2fc03a4f");
        Client client = buildClientForDelete();

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, client);

        // Assert
        RestResponse expectedResponse =
            new RestResponse("KVDB deleted successfully.", RestStatus.CREATED.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.CREATED, bytesRestResponse.status());
        // Verify that the integration was modified
        ArgumentCaptor<IndexRequest> indexCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(client).index(indexCaptor.capture());
        IndexRequest capturedRequest = indexCaptor.getValue();
        assertEquals(".cti-integrations", capturedRequest.index());
        assertEquals("integration-1", capturedRequest.id());
    }

    /**
     * Test the {@link RestDeleteKvdbAction#handleRequest(RestRequest, Client)} method when the kvdb has not
     * been deleted (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteKvdb400() throws IOException {
        // Mock
        RestRequest request = buildRequest(null, null);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse expectedResponse =
            new RestResponse("KVDB ID is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
    }

    /**
     * Test the {@link RestDeleteKvdbAction#handleRequest(RestRequest, Client)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb500() throws IOException {
        // Mock
        this.action = new RestDeleteKvdbAction(null);
        RestRequest request = buildRequest(null, "k_82e215c4-988a-4f64-8d15-b98b2fc03a4f");

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse expectedResponse =
            new RestResponse(
                "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, bytesRestResponse.status());
    }

    private RestRequest buildRequest(String payload, String kvdbId) {
        FakeRestRequest.Builder builder = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY);
        if (payload != null) {
            builder.withContent(new BytesArray(payload), XContentType.JSON);
        }
        if (kvdbId != null) {
            builder.withParams(Map.of("id", kvdbId, "kvdb_id", kvdbId));
        }
        return builder.build();
    }

    private RestResponse parseResponse(BytesRestResponse response) {
        JsonNode node = FixtureFactory.from(response.content().utf8ToString());
        return new RestResponse(node.get("message").asText(), node.get("status").asInt());
    }

    private Client buildClientForDelete() throws IOException {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        doAnswer(
            invocation -> {
                return null;
            })
            .when(client)
            .delete(any(DeleteRequest.class), any());

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        SearchResponse searchResponse = mock(SearchResponse.class);
        org.opensearch.search.SearchHit hit =
            new org.opensearch.search.SearchHit(
                0, "integration-1", Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(
            new BytesArray(
                "{\"document\":{\"kvdbs\":[\"k_82e215c4-988a-4f64-8d15-b98b2fc03a4f\"]}}"));
        org.opensearch.search.SearchHits hits =
            new org.opensearch.search.SearchHits(
                new org.opensearch.search.SearchHit[] {hit},
                new TotalHits(1, TotalHits.Relation.EQUAL_TO),
                1.0f);
        when(searchResponse.getHits()).thenReturn(hits);
        when(client.search(any(SearchRequest.class)).actionGet()).thenReturn(searchResponse);

        return client;
    }
}
