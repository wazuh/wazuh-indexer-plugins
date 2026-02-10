/*
 * Copyright (C) 2026, Wazuh Inc.
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
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.util.*;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestPutPolicyAction} class. This test suite validates the REST API
 * endpoint responsible for updating Policy configurations.
 *
 * <p>Tests verify Policy update requests, proper handling of Policy data, and appropriate HTTP
 * response codes for successful Policy updates and error scenarios.
 */
public class RestPutPolicyActionTests extends OpenSearchTestCase {
    private SpaceService service;
    private RestPutPolicyAction action;
    private NodeClient client;
    private AutoCloseable mocks;

    @Mock private IndexResponse indexResponse;
    @Mock private SearchResponse searchResponse;

    /**
     * Set up the tests.
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        this.service = mock(SpaceService.class);
        this.client = mock(NodeClient.class, Answers.RETURNS_DEEP_STUBS);
        Settings settings = Settings.builder().build();
        PluginSettings.getInstance(settings);

        this.action = new RestPutPolicyAction(this.service, this.client);

        Map<String, Object> policy = new HashMap<>();
        Map<String, Object> document = new HashMap<>();
        Map<String, Object> hash = new HashMap<>();
        Map<String, Object> space = new HashMap<>();
        document.put(Constants.KEY_ID, "12345");
        document.put(Constants.KEY_INTEGRATIONS, List.of("integration-1"));
        hash.put("sha256", "12345");
        space.put(Constants.KEY_NAME, Space.DRAFT.toString());
        policy.put(Constants.KEY_DOCUMENT, document);
        policy.put(Constants.KEY_HASH, hash);
        policy.put(Constants.KEY_SPACE, space);
        when(this.service.getPolicy(anyString())).thenReturn(policy);

        // Mock SearchHits properly
        SearchHit searchHit =
                new SearchHit(0, "draft-policy-id", Collections.emptyMap(), Collections.emptyMap());
        SearchHits searchHits =
                new SearchHits(
                        new SearchHit[] {searchHit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);
        when(this.searchResponse.getHits()).thenReturn(searchHits);

        PlainActionFuture<SearchResponse> searchFuture = PlainActionFuture.newFuture();
        searchFuture.onResponse(this.searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);
    }

    /**
     * Tear down the tests.
     *
     * @throws Exception rethrown from parent method
     */
    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.mocks != null) {
            this.mocks.close();
        }
    }

    /** If the request adds or removes integrations to the policy, then return a 400 error. */
    public void testPutPolicy_UpdateModifiesIntegrations_400() {
        // Mock root_decoder existence
        var getRequest =
                mock(org.opensearch.action.get.GetRequestBuilder.class, Answers.RETURNS_DEEP_STUBS);
        var getResponse = mock(org.opensearch.action.get.GetResponse.class);
        when(this.client.prepareGet(any(String.class), any(String.class))).thenReturn(getRequest);
        when(getRequest.setFetchSource(false)).thenReturn(getRequest);
        when(getRequest.get()).thenReturn(getResponse);
        when(getResponse.isExists()).thenReturn(true);
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration/wazuh-core/0\"],"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        // Mock search response to return existing draft policy
        PlainActionFuture<SearchResponse> searchFuture = PlainActionFuture.newFuture();
        searchFuture.onResponse(this.searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);
        // We need to mock getHits() but SearchHits is final, so the test will handle
        // NullPointerException
        // The actual method in RestPutPolicyAction will catch any exception from searchByQuery

        // Mock index response
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request is
     * complete and a draft policy already exists. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_UpdateExisting_200() {
        // Mock root_decoder existence
        var getRequest =
                mock(org.opensearch.action.get.GetRequestBuilder.class, Answers.RETURNS_DEEP_STUBS);
        var getResponse = mock(org.opensearch.action.get.GetResponse.class);
        when(this.client.prepareGet(any(String.class), any(String.class))).thenReturn(getRequest);
        when(getRequest.setFetchSource(false)).thenReturn(getRequest);
        when(getRequest.get()).thenReturn(getResponse);
        when(getResponse.isExists()).thenReturn(true);
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        // Mock search response to return existing draft policy
        PlainActionFuture<SearchResponse> searchFuture = PlainActionFuture.newFuture();
        searchFuture.onResponse(this.searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);
        // We need to mock getHits() but SearchHits is final, so the test will handle
        // NullPointerException
        // The actual method in RestPutPolicyAction will catch any exception from searchByQuery

        // Mock index response
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        assertEquals("test-policy-id", response.getMessage());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request is
     * complete and no draft policy exists. The expected response is: {200, RestResponse} with a new
     * policy created.
     */
    public void testPutPolicy_CreateNew_200() {
        // Mock root_decoder existence
        var getRequest =
                mock(org.opensearch.action.get.GetRequestBuilder.class, Answers.RETURNS_DEEP_STUBS);
        var getResponse = mock(org.opensearch.action.get.GetResponse.class);
        when(this.client.prepareGet(any(String.class), any(String.class))).thenReturn(getRequest);
        when(getRequest.setFetchSource(false)).thenReturn(getRequest);
        when(getRequest.get()).thenReturn(getResponse);
        when(getResponse.isExists()).thenReturn(true);
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"author\": \"Test Author\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"\","
                        + "\"references\": []"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        // Mock search response to return no existing policy

        PlainActionFuture<SearchResponse> searchFuture = PlainActionFuture.newFuture();
        searchFuture.onResponse(this.searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        // Mock index response
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request has no
     * content. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_NoContent_400() {
        // Arrange
        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request has
     * invalid JSON content. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_InvalidJson_400() {
        // Arrange
        String invalidJson = "{invalid json content";
        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(invalidJson), XContentType.JSON)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains(Constants.E_400_INVALID_REQUEST_BODY));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request is
     * missing the 'resource' field. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_MissingResourceField_400() {
        // Arrange
        String policyJson = "{\"type\": \"policy\"}";
        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("is required"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the resource object
     * is missing required fields. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_MissingRequiredFields_400() {
        // Arrange - missing author, description, documentation, and references
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": []"
                        + "}"
                        + "}";
        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("is required"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the indexing
     * operation fails. The expected response is: {500, RestResponse}
     */
    public void testPutPolicy_IndexingFails_500() {
        // Mock root_decoder existence
        var getRequest =
                mock(org.opensearch.action.get.GetRequestBuilder.class, Answers.RETURNS_DEEP_STUBS);
        var getResponse = mock(org.opensearch.action.get.GetResponse.class);
        when(this.client.prepareGet(any(String.class), any(String.class))).thenReturn(getRequest);
        when(getRequest.setFetchSource(false)).thenReturn(getRequest);
        when(getRequest.get()).thenReturn(getResponse);
        when(getResponse.isExists()).thenReturn(true);
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"author\": \"Test Author\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"\","
                        + "\"references\": []"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        // Mock search response
        PlainActionFuture<SearchResponse> searchFuture = PlainActionFuture.newFuture();
        searchFuture.onResponse(this.searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        // Mock index to throw exception
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onFailure(new IOException("Indexing failed"));
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        assertEquals(Constants.E_500_INTERNAL_SERVER_ERROR, response.getMessage());
    }
}
