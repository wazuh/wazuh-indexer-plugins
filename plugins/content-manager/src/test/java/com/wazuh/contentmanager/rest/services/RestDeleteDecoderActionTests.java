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

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestDeleteDecoderAction} class. This test suite validates the REST API
 * endpoint responsible for deleting new CTI Decoders.
 *
 * <p>Tests verify Decoder delete requests, proper handling of Decoder data, and appropriate HTTP
 * response codes for successful Decoder delete errors.
 */
public class RestDeleteDecoderActionTests extends OpenSearchTestCase {

    private RestDeleteDecoderAction action;
    private Client client;
    private PolicyHashService policyHashService;

    /** Initialize PluginSettings singleton once for all tests. */
    @BeforeClass
    public static void setUpClass() {
        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
            // Already initialized
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
        EngineService engine = mock(EngineService.class);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        this.policyHashService = mock(PolicyHashService.class);

        this.action = spy(new RestDeleteDecoderAction(engine));
        this.action.setPolicyHashService(this.policyHashService);
    }

    /** Helper to mock decoder existence and space verification for deletion. */
    private void mockDecoderInSpace(String id, String space, boolean exists) {
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);

        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(exists);
        if (exists) {
            Map<String, Object> source = new HashMap<>();
            source.put(Constants.KEY_SPACE, Map.of(Constants.KEY_NAME, space));
            source.put(Constants.KEY_DOCUMENT, Map.of(Constants.KEY_ID, id));
            when(response.getSourceAsMap()).thenReturn(source);
            when(response.getSourceAsString())
                    .thenReturn(
                            "{\"document\":{\"id\":\"" + id + "\"},\"space\":{\"name\":\"" + space + "\"}}");
        }

        GetRequestBuilder getBuilder = mock(GetRequestBuilder.class, Answers.RETURNS_SELF);
        when(this.client.prepareGet(anyString(), eq(id))).thenReturn(getBuilder);
        when(getBuilder.get()).thenReturn(response);
    }

    /** Helper to mock unlinking logic search results. */
    private void mockUnlinkSearch(String decoderId) {
        SearchHit hit =
                new SearchHit(0, "integration-1", Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(new BytesArray("{\"document\":{\"decoders\":[\"" + decoderId + "\"]}}"));
        SearchHits hits =
                new SearchHits(new SearchHit[] {hit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);

        SearchResponse searchResponse = mock(SearchResponse.class);
        when(searchResponse.getHits()).thenReturn(hits);

        PlainActionFuture<SearchResponse> searchFuture = PlainActionFuture.newFuture();
        searchFuture.onResponse(searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.OK);
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
    }

    /**
     * Test the {@link RestDeleteDecoderAction#executeRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteDecoder200() throws IOException {
        String decoderId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", decoderId))
                        .build();

        this.mockDecoderInSpace(decoderId, "draft", true);
        this.mockUnlinkSearch(decoderId);

        RestResponse response = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals(decoderId, response.getMessage());
        verify(this.client).delete(any(DeleteRequest.class), any());
    }

    /**
     * Test the {@link RestDeleteDecoderAction#executeRequest(RestRequest, Client)} method when the
     * decoder ID is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteDecoder400_MissingId() throws IOException {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();
        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestDeleteDecoderAction#executeRequest(RestRequest, Client)} method when the
     * decoder ID is not a valid UUID. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteDecoder400_InvalidUUID() throws IOException {
        // "not@valid#uuid" violates the alphanumeric/hyphen regex in DocumentValidations
        String invalidId = "not@valid#uuid";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", invalidId))
                        .build();

        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestDeleteDecoderAction#executeRequest(RestRequest, Client)} method when the
     * decoder is not found. The expected response is: {404, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteDecoder404_NotFound() throws IOException {
        String decoderId = "missing-id";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", decoderId))
                        .build();

        this.mockDecoderInSpace(decoderId, "draft", false);
        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.NOT_FOUND.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestDeleteDecoderAction#executeRequest(RestRequest, Client)} method when the
     * decoder is not in the draft space. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteDecoder400_NotInDraft() throws IOException {
        String decoderId = "prod-id";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", decoderId))
                        .build();

        this.mockDecoderInSpace(decoderId, "standard", true);
        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("is not in draft space"));
    }

    /**
     * Test the {@link RestDeleteDecoderAction#executeRequest(RestRequest, Client)} method when engine
     * service is not initialized. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteDecoder500_EngineNotInitialized() throws IOException {
        // Initialize action with null engine
        this.action = spy(new RestDeleteDecoderAction(null));
        this.action.setPolicyHashService(this.policyHashService);

        String decoderId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", decoderId))
                        .build();

        // Mock index as existing so it proceeds to hit the (null) engine service
        this.mockDecoderInSpace(decoderId, "draft", true);

        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestDeleteDecoderAction#executeRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteDecoder500_UnexpectedError() throws IOException {
        String decoderId = "error-id";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", decoderId))
                        .build();

        // Simulate failure on the admin/indices chain
        when(this.client.admin().indices().prepareExists(anyString()))
                .thenThrow(new RuntimeException("Simulated failure"));

        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }
}
