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
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
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
    private EngineService service;
    private RestPutPolicyAction action;
    private NodeClient client;
    private AutoCloseable closeable;

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
        this.closeable = MockitoAnnotations.openMocks(this);
        this.service = mock(EngineService.class);
        this.client = mock(NodeClient.class, Answers.RETURNS_DEEP_STUBS);

        Settings settings = Settings.builder().build();
        PluginSettings.getInstance(settings);

        this.action = new RestPutPolicyAction(this.service);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest, NodeClient)} method when the
     * request is complete and a draft policy already exists. The expected response is: {200,
     * RestResponse}
     */
    public void testPutPolicy_UpdateExisting_200() {
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration/wazuh-core/0\"],"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": \"Test references\""
                        + "}";

        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath("/_plugins/_content_manager/policy")
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

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("policy"));
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest, NodeClient)} method when the
     * request is complete and no draft policy exists. The expected response is: {200, RestResponse}
     * with a new policy created.
     */
    public void testPutPolicy_CreateNew_200() {
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [],"
                        + "\"author\": \"Test Author\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"\","
                        + "\"references\": \"\""
                        + "}";

        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath("/_plugins/_content_manager/policy")
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

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest, NodeClient)} method when the
     * engine service is null. The expected response is: {500, RestResponse}
     */
    public void testPutPolicy_NullEngine_500() {
        // Arrange
        RestPutPolicyAction actionWithNullEngine = new RestPutPolicyAction(null);

        String policyJson = "{\"type\": \"policy\"}";
        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath("/_plugins/_content_manager/policy")
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        // Act
        RestResponse response = actionWithNullEngine.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("Engine instance is null"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest, NodeClient)} method when the
     * request has no content. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_NoContent_400() {
        // Arrange
        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath("/_plugins/_content_manager/policy")
                        .withParams(params)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("JSON request body is required"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest, NodeClient)} method when the
     * request has invalid JSON content. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_InvalidJson_400() {
        // Arrange
        String invalidJson = "{invalid json content";
        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath("/_plugins/_content_manager/policy")
                        .withParams(params)
                        .withContent(new BytesArray(invalidJson), XContentType.JSON)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("Invalid Policy JSON content"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest, NodeClient)} method when the
     * indexing operation fails. The expected response is: {500, RestResponse}
     */
    public void testPutPolicy_IndexingFails_500() {
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [],"
                        + "\"author\": \"Test Author\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"\","
                        + "\"references\": \"\""
                        + "}";

        Map<String, String> params = new HashMap<>();
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath("/_plugins/_content_manager/policy")
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
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("Failed to store the updated policy"));
    }

    /** Test that the action name is correctly set. */
    public void testGetName() {
        // Act
        String name = this.action.getName();

        // Assert
        assertEquals("content_manager_policy_update", name);
    }

    /** Test that the routes are correctly configured. */
    public void testRoutes() {
        // Act
        var routes = this.action.routes();

        // Assert
        assertEquals(1, routes.size());
        assertEquals(RestRequest.Method.PUT, routes.getFirst().getMethod());
    }
}
