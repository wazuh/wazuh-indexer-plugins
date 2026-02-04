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
import org.opensearch.action.get.GetResponse;
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

import java.util.Collections;
import java.util.Map;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestDeleteDecoderAction} class. This test suite validates the REST API
 * endpoint responsible for deleting new CTI Decoders.
 *
 * <p>Tests verify Decoder delete requests, proper handling of Decoder data, and appropriate HTTP
 * response codes for successful Decoder delete errors.
 */
public class RestDeleteDecoderActionTests extends OpenSearchTestCase {
    private RestDeleteDecoderAction action;

    /** Initialize PluginSettings singleton once for all tests. */
    @BeforeClass
    public static void setUpClass() {
        // Initialize PluginSettings singleton - it will persist across all tests
        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
            // Already initialized, ignore
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
        EngineService service = mock(EngineService.class);
        this.action = new RestDeleteDecoderAction(service);
    }

    /**
     * Test the {@link RestDeleteDecoderAction#handleRequest(RestRequest)} method when the request is
     * complete. The expected response is: {200, RestResponse}
     */
    public void testDeleteDecoder200() {
        // Mock
        RestRequest request = this.buildRequest("d_82e215c4-988a-4f64-8d15-b98b2fc03a4f");
        Client client = this.buildClientForDelete();

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, client);

        // Assert
        RestResponse expectedResponse =
                new RestResponse("Decoder deleted successfully.", RestStatus.OK.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.OK, bytesRestResponse.status());
    }

    /**
     * Test the {@link RestDeleteDecoderAction#handleRequest(RestRequest)} method when the decoder has
     * not been deleted (mock). The expected response is: {400, RestResponse}
     */
    public void testDeleteDecoder400() {
        // Mock
        RestRequest request = this.buildRequest(null);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse expectedResponse =
                new RestResponse("Decoder ID is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
    }

    /**
     * Test the {@link RestDeleteDecoderAction#handleRequest(RestRequest)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     */
    public void testDeleteDecoder500() {
        // Mock
        this.action = new RestDeleteDecoderAction(null);
        RestRequest request = this.buildRequest("d_82e215c4-988a-4f64-8d15-b98b2fc03a4f");

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse expectedResponse =
                new RestResponse(
                        "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, bytesRestResponse.status());
    }

    /**
     * Test that integration field in DELETE request body returns 400 Bad Request.
     */
    public void testDeleteDecoderWithIntegrationInBodyReturns400() {
        // Arrange
        String payloadWithIntegration = "{\"integration\": \"integration-1\"}";
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(payloadWithIntegration), XContentType.JSON)
                        .withParams(Map.of("id", "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f"));
        RestRequest request = builder.build();

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        "Integration field is not allowed in DELETE requests.",
                        RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
    }

    private RestRequest buildRequest(String decoderId) {
        FakeRestRequest.Builder builder = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY);
        if (decoderId != null) {
            builder.withParams(Map.of("id", decoderId, "decoder_id", decoderId));
        }
        return builder.build();
    }

    private RestResponse parseResponse(BytesRestResponse response) {
        JsonNode node = FixtureFactory.from(response.content().utf8ToString());
        return new RestResponse(node.get("message").asText(), node.get("status").asInt());
    }

    private Client buildClientForDelete() {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        // Mock ContentIndex.exists() - decoder exists
        GetResponse existsResponse = mock(GetResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
                .thenReturn(existsResponse);

        // Mock validateDecoderSpace - decoder exists and is in draft space
        GetResponse spaceResponse = mock(GetResponse.class);
        when(spaceResponse.isExists()).thenReturn(true);
        when(spaceResponse.getSourceAsMap()).thenReturn(Map.of("space", Map.of("name", "draft")));
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(spaceResponse);

        doAnswer(invocation -> null).when(client).delete(any(DeleteRequest.class), any());

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
                        "{\"document\":{\"decoders\":[\"d_82e215c4-988a-4f64-8d15-b98b2fc03a4f\"]}}"));
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
