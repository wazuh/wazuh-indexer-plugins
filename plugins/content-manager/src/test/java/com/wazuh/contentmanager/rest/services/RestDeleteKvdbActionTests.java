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
 * Unit tests for the {@link RestDeleteKvdbAction} class. This test suite validates the REST API
 * endpoint responsible for deleting new CTI Kvdbs.
 *
 * <p>Tests verify Kvdb delete requests, proper handling of Kvdb data, and appropriate HTTP response
 * codes for successful Kvdb delete errors.
 */
public class RestDeleteKvdbActionTests extends OpenSearchTestCase {

    private RestDeleteKvdbAction action;
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
        EngineService service = mock(EngineService.class);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        this.policyHashService = mock(PolicyHashService.class);

        this.action = spy(new RestDeleteKvdbAction(service));
        this.action.setPolicyHashService(this.policyHashService);
    }

    /** Helper to mock KVDB existence and space verification for deletion. */
    private void mockKvdbInSpace(String id, String space, boolean exists) {
        // 1. Mock IndexHelper.indexExists
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);

        // 2. Create a unified GetResponse mock
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

        // 3. Mock the GetRequestBuilder chain to be robust against setFetchSource calls
        GetRequestBuilder getBuilder = mock(GetRequestBuilder.class, Answers.RETURNS_SELF);
        when(this.client.prepareGet(anyString(), eq(id))).thenReturn(getBuilder);
        when(getBuilder.get()).thenReturn(response);
    }

    /** Helper to mock unlinking logic search results. */
    private void mockUnlinkSearch(String kvdbId) {
        SearchHit hit =
                new SearchHit(0, "integration-1", Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(new BytesArray("{\"document\":{\"kvdbs\":[\"" + kvdbId + "\"]}}"));
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
     * Test the {@link RestDeleteKvdbAction#executeRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb200() throws IOException {
        String kvdbId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        this.mockKvdbInSpace(kvdbId, "draft", true);
        this.mockUnlinkSearch(kvdbId);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(kvdbId, actualResponse.getMessage());
        verify(this.client).delete(any(DeleteRequest.class), any());
    }

    /**
     * Test the {@link RestDeleteKvdbAction#executeRequest(RestRequest, Client)} method when the kvdb
     * ID is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb400_MissingId() throws IOException {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();
        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestDeleteKvdbAction#executeRequest(RestRequest, Client)} method when the kvdb
     * ID is not a valid UUID. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb400_InvalidUUID() throws IOException {
        String invalidId = "not@valid#uuid";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", invalidId))
                        .build();

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestDeleteKvdbAction#executeRequest(RestRequest, Client)} method when the kvdb
     * is not found. The expected response is: {404, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb404_NotFound() throws IOException {
        String kvdbId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        this.mockKvdbInSpace(kvdbId, "draft", false);
        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.NOT_FOUND.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestDeleteKvdbAction#executeRequest(RestRequest, Client)} method when the kvdb
     * is not in the draft space. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb400_NotInDraft() throws IOException {
        String kvdbId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        this.mockKvdbInSpace(kvdbId, "standard", true);
        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("is not in draft space"));
    }

    /**
     * Test the {@link RestDeleteKvdbAction#executeRequest(RestRequest, Client)} method when engine
     * service is not initialized. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb500_EngineNotInitialized() throws IOException {
        this.action = spy(new RestDeleteKvdbAction(null));
        this.action.setPolicyHashService(this.policyHashService);
        String kvdbId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        this.mockKvdbInSpace(kvdbId, "draft", true);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestDeleteKvdbAction#executeRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb500_UnexpectedError() throws IOException {
        String kvdbId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        when(this.client.admin()).thenThrow(new RuntimeException("Simulated failure"));

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());
    }
}
