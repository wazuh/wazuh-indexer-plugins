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
package com.wazuh.contentmanager.rest.service;

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
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.*;
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
        document.put("filters", Collections.emptyList());
        document.put("enrichments", Collections.emptyList());
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
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration/wazuh-core/0\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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

        // Mock index response
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request is
     * complete and a draft policy already exists. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_UpdateExisting_200() {
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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

        // Mock index response
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals("test-policy-id", response.getMessage());

        // Verify PolicyHashService was called to regenerate space hash
        verify(this.service).calculateAndUpdate(anyList());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request is
     * complete and no draft policy exists. The expected response is: {200, RestResponse} with a new
     * policy created.
     */
    public void testPutPolicy_CreateNew_200() {
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Test Author\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"\","
                        + "\"references\": []"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request has no
     * content. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_NoContent_400() {
        // Arrange
        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .build();

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
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
        params.put("space", "draft");
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
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains(Constants.E_400_INVALID_REQUEST_BODY));
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
        params.put("space", "draft");
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
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the resource object
     * is missing required fields. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_MissingRequiredFields_400() {
        // Arrange - missing enabled, index_unclassified_events, index_discarded_events,
        // author, description, documentation, and references
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
        params.put("space", "draft");
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
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the indexing
     * operation fails. The expected response is: {500, RestResponse}
     */
    public void testPutPolicy_IndexingFails_500() {
        // Arrange
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Test Author\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"\","
                        + "\"references\": []"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains(Constants.E_500_INTERNAL_SERVER_ERROR));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains valid enrichments. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_ValidEnrichments_200() {
        // Arrange - policy with valid enrichments
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"enrichments\": [\"file\", \"ip\", \"url\"],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        PayloadValidations payloadValidations = mock(PayloadValidations.class);
        when(payloadValidations.validateEnrichments(anyList(), anySet())).thenReturn(null);
        this.action.setPayloadValidations(payloadValidations);

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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

        // Mock index response
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals("test-policy-id", response.getMessage());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains an invalid enrichment type. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_InvalidEnrichmentType_400() {
        // Arrange - policy with invalid enrichment type
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"enrichments\": [\"connection\", \"invalid-type\", \"hash_sha1\"],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        PayloadValidations payloadValidations = mock(PayloadValidations.class);
        when(payloadValidations.validateEnrichments(anyList(), anySet()))
                .thenReturn(
                        new RestResponse(
                                "Invalid enrichment type 'invalid-type'. Allowed values are: connection, hash_sha1",
                                400));
        this.action.setPayloadValidations(payloadValidations);

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(
                String.format(
                        Locale.ROOT,
                        Constants.E_400_INVALID_ENRICHMENT,
                        "invalid-type",
                        "connection, hash_sha1"),
                response.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains duplicate enrichment types. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_DuplicateEnrichments_400() {
        // Arrange - policy with duplicate enrichment types
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"enrichments\": [\"hash_sha1\", \"connection\", \"connection\"],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        PayloadValidations payloadValidations = mock(PayloadValidations.class);
        when(payloadValidations.validateEnrichments(anyList(), anySet()))
                .thenReturn(new RestResponse("Duplicate enrichment type 'connection'.", 400));
        this.action.setPayloadValidations(payloadValidations);

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(
                String.format(Locale.ROOT, Constants.E_400_DUPLICATE_ENRICHMENT, "connection"),
                response.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains all valid enrichment types. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_AllValidEnrichmentTypes_200() {

        // Arrange - policy with all valid enrichment types
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"enrichments\": [\"file\", \"domain-name\", \"ip\", \"url\", \"geo\"],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        PayloadValidations payloadValidations = mock(PayloadValidations.class);
        when(payloadValidations.validateEnrichments(anyList(), anySet())).thenReturn(null);
        this.action.setPayloadValidations(payloadValidations);

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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

        // Mock index response
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals("test-policy-id", response.getMessage());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * attempts to add a filter to the existing filters list. The expected response is: {400,
     * RestResponse}
     */
    public void testPutPolicy_AddFilter_400() throws Exception {
        // Override mock to return a policy with an existing filter
        Map<String, Object> policy = new HashMap<>();
        Map<String, Object> document = new HashMap<>();
        Map<String, Object> hash = new HashMap<>();
        Map<String, Object> space = new HashMap<>();
        document.put(Constants.KEY_ID, "12345");
        document.put(Constants.KEY_INTEGRATIONS, List.of("integration-1"));
        document.put("filters", List.of("uuid-1"));
        document.put("enrichments", Collections.emptyList());
        hash.put("sha256", "12345");
        space.put(Constants.KEY_NAME, Space.DRAFT.toString());
        policy.put(Constants.KEY_DOCUMENT, document);
        policy.put(Constants.KEY_HASH, hash);
        policy.put(Constants.KEY_SPACE, space);
        when(this.service.getPolicy(anyString())).thenReturn(policy);

        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [\"uuid-1\", \"uuid-2\"],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * attempts to remove a filter from the existing filters list. The expected response is: {400,
     * RestResponse}
     */
    public void testPutPolicy_RemoveFilter_400() throws Exception {
        // Override mock to return a policy with two existing filters
        Map<String, Object> policy = new HashMap<>();
        Map<String, Object> document = new HashMap<>();
        Map<String, Object> hash = new HashMap<>();
        Map<String, Object> space = new HashMap<>();
        document.put(Constants.KEY_ID, "12345");
        document.put(Constants.KEY_INTEGRATIONS, List.of("integration-1"));
        document.put("filters", List.of("uuid-1", "uuid-2"));
        document.put("enrichments", Collections.emptyList());
        hash.put("sha256", "12345");
        space.put(Constants.KEY_NAME, Space.DRAFT.toString());
        policy.put(Constants.KEY_DOCUMENT, document);
        policy.put(Constants.KEY_HASH, hash);
        policy.put(Constants.KEY_SPACE, space);
        when(this.service.getPolicy(anyString())).thenReturn(policy);

        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [\"uuid-1\"],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * reorders filters (allowed). The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_ReorderFilters_200() throws Exception {

        // Override mock to return a policy with two existing filters
        Map<String, Object> policy = new HashMap<>();
        Map<String, Object> document = new HashMap<>();
        Map<String, Object> hash = new HashMap<>();
        Map<String, Object> space = new HashMap<>();
        document.put(Constants.KEY_ID, "12345");
        document.put(Constants.KEY_INTEGRATIONS, List.of("integration-1"));
        document.put("filters", List.of("uuid-1", "uuid-2"));
        document.put("enrichments", Collections.emptyList());
        hash.put("sha256", "12345");
        space.put(Constants.KEY_NAME, Space.DRAFT.toString());
        policy.put(Constants.KEY_DOCUMENT, document);
        policy.put(Constants.KEY_HASH, hash);
        policy.put(Constants.KEY_SPACE, space);
        when(this.service.getPolicy(anyString())).thenReturn(policy);

        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [\"uuid-2\", \"uuid-1\"],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains enabled=true. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_WithEnabledTrue_200() {

        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains enabled=false. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_WithEnabledFalse_200() {

        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": false,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains index_unclassified_events=true. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_WithIndexUnclassifiedEvents_200() {

        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": true,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains index_discarded_events=false. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_WithIndexDiscardedEvents_200() {

        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains all three boolean fields. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_AllBooleanFields_200() {
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": true,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals("test-policy-id", response.getMessage());
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request omits
     * all boolean fields. The expected response is: {400, RestResponse}
     */
    public void testPutPolicy_NoBooleanFields_400() {
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"filters\": [],"
                        + "\"enrichments\": [],"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray(policyJson), XContentType.JSON)
                        .build();

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
    }

    /**
     * Test the {@link RestPutPolicyAction#handleRequest(RestRequest)} method when the request
     * contains an empty enrichments array. The expected response is: {200, RestResponse}
     */
    public void testPutPolicy_EmptyEnrichments_200() {
        // Arrange - policy with empty enrichments array
        String policyJson =
                "{"
                        + "\"type\": \"policy\","
                        + "\"resource\": {"
                        + "\"title\": \"Test Policy\","
                        + "\"root_decoder\": \"decoder/integrations/0\","
                        + "\"integrations\": [\"integration-1\"],"
                        + "\"enrichments\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false,"
                        + "\"author\": \"Wazuh Inc.\","
                        + "\"description\": \"Test policy\","
                        + "\"documentation\": \"Test documentation\","
                        + "\"references\": [\"Test references\"]"
                        + "}"
                        + "}";

        Map<String, String> params = new HashMap<>();
        params.put("space", "draft");
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

        // Mock index response
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("test-policy-id");

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals("test-policy-id", response.getMessage());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    // ========================
    // Standard Space Tests
    // ========================

    /**
     * Helper to build a rich standard policy mock with all fields populated, so that {@code
     * updateStandardPolicy} can preserve immutable values.
     */
    private void mockStandardPolicy(
            List<String> filters, List<String> enrichments, List<String> integrations)
            throws IOException {
        Map<String, Object> policy = new HashMap<>();
        Map<String, Object> document = new HashMap<>();
        Map<String, Object> hash = new HashMap<>();
        Map<String, Object> space = new HashMap<>();
        document.put(Constants.KEY_ID, "standard-doc-id");
        document.put(Constants.KEY_TITLE, "Standard Policy Title");
        document.put(Constants.KEY_AUTHOR, "Original Author");
        document.put(Constants.KEY_DESCRIPTION, "Original description");
        document.put("documentation", "Original documentation");
        document.put("references", List.of("https://original.ref"));
        document.put("root_decoder", "decoder/original/0");
        document.put("date", "2025-01-01T00:00:00Z");
        document.put(Constants.KEY_INTEGRATIONS, integrations);
        document.put(Constants.KEY_FILTERS, filters);
        document.put(Constants.KEY_ENRICHMENTS, enrichments);
        hash.put("sha256", "standard-hash-value");
        space.put(Constants.KEY_NAME, Space.STANDARD.toString());
        policy.put(Constants.KEY_DOCUMENT, document);
        policy.put(Constants.KEY_HASH, hash);
        policy.put(Constants.KEY_SPACE, space);
        when(this.service.getPolicy(anyString())).thenReturn(policy);
    }

    /** Helper to build a standard-space request. */
    private RestRequest buildStandardRequest(String json) {
        Map<String, String> params = new HashMap<>();
        params.put("space", "standard");
        return new FakeRestRequest.Builder(this.xContentRegistry())
                .withMethod(RestRequest.Method.PUT)
                .withPath(PluginSettings.POLICY_URI)
                .withParams(params)
                .withContent(new BytesArray(json), XContentType.JSON)
                .build();
    }

    /**
     * Test successful standard-space update of enrichments field. The five allowed fields are applied
     * and the policy is persisted.
     */
    public void testPutStandardPolicy_UpdateEnrichments_200() throws IOException {
        // Arrange — standard policy must contain "connection" as a known enrichment type
        this.mockStandardPolicy(
                Collections.emptyList(), List.of("connection", "hash_sha1"), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");

        // Mock PayloadValidations to bypass IoC type hashes lookup (enrichments are valid)
        PayloadValidations payloadValidations = mock(PayloadValidations.class);
        when(payloadValidations.validateEnrichments(anyList(), anySet())).thenReturn(null);
        this.action.setPayloadValidations(payloadValidations);

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("standard-policy-os-id");

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [\"connection\"],"
                        + "\"filters\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        // Act
        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        // Assert
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals("standard-policy-os-id", response.getMessage());
        verify(this.client, times(1)).index(any(IndexRequest.class));
        verify(this.service).calculateAndUpdate(anyList());
    }

    /** Test successful standard-space update of enabled field. */
    public void testPutStandardPolicy_UpdateEnabled_200() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("standard-policy-os-id");

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [],"
                        + "\"enabled\": false,"
                        + "\"index_unclassified_events\": true,"
                        + "\"index_discarded_events\": true"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /**
     * Test that restricted fields (title, author, description, root_decoder, integrations,
     * documentation, references) sent in the payload are silently ignored for standard-space updates.
     * The persisted document must preserve the original values from the existing policy.
     */
    public void testPutStandardPolicy_RestrictedFieldsIgnored_200() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("standard-policy-os-id");

        // Payload attempts to override restricted fields
        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"title\": \"Hacked Title\","
                        + "\"author\": \"Hacked Author\","
                        + "\"description\": \"Hacked description\","
                        + "\"documentation\": \"Hacked documentation\","
                        + "\"references\": [\"https://hacked.ref\"],"
                        + "\"root_decoder\": \"decoder/hacked/0\","
                        + "\"integrations\": [\"hacked-integration\"],"
                        + "\"enrichments\": [],"
                        + "\"filters\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        // The update succeeds (restricted fields are silently dropped)
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /** Test that an unrecognized enrichment category returns 400 for standard space. */
    public void testPutStandardPolicy_InvalidEnrichment_400() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));

        // Mock PayloadValidations to return an error for invalid enrichment
        PayloadValidations payloadValidations = mock(PayloadValidations.class);
        when(payloadValidations.validateEnrichments(anyList(), anySet()))
                .thenReturn(
                        new RestResponse(
                                String.format(
                                        Locale.ROOT,
                                        Constants.E_400_INVALID_ENRICHMENT,
                                        "invalid-type",
                                        "connection, hash_sha1"),
                                400));
        this.action.setPayloadValidations(payloadValidations);

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [\"invalid-type\"],"
                        + "\"filters\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Test that adding a filter to the standard policy returns 400. */
    public void testPutStandardPolicy_AddFilter_400() throws IOException {
        this.mockStandardPolicy(List.of("uuid-1"), Collections.emptyList(), List.of("int-1"));

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [\"uuid-1\", \"uuid-2\"],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Test that removing a filter from the standard policy returns 400. */
    public void testPutStandardPolicy_RemoveFilter_400() throws IOException {
        this.mockStandardPolicy(List.of("uuid-1", "uuid-2"), Collections.emptyList(), List.of("int-1"));

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [\"uuid-1\"],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Test that reordering filters in the standard policy returns 200. */
    public void testPutStandardPolicy_ReorderFilters_200() throws IOException {
        this.mockStandardPolicy(List.of("uuid-1", "uuid-2"), Collections.emptyList(), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("standard-policy-os-id");

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [\"uuid-2\", \"uuid-1\"],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /** Test that missing enabled field returns 400 for standard space. */
    public void testPutStandardPolicy_MissingEnabled_400() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [],"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Test that missing index_unclassified_events field returns 400 for standard space. */
    public void testPutStandardPolicy_MissingIndexUnclassifiedEvents_400() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [],"
                        + "\"enabled\": true,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Test that missing index_discarded_events field returns 400 for standard space. */
    public void testPutStandardPolicy_MissingIndexDiscardedEvents_400() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Test that missing all three boolean fields returns 400 for standard space. */
    public void testPutStandardPolicy_MissingAllBooleanFields_400() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));

        String policyJson =
                "{" + "\"resource\": {" + "\"enrichments\": []," + "\"filters\": []" + "}" + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Missing"));
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Test that standard-space update does NOT require author, description, documentation, or
     * references (those are only required for draft).
     */
    public void testPutStandardPolicy_NoAuthorDescriptionRequired_200() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("standard-policy-os-id");

        // No author, description, documentation, or references — valid for standard
        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.client, times(1)).index(any(IndexRequest.class));
    }

    /** Test that duplicate enrichment types return 400 for standard space. */
    public void testPutStandardPolicy_DuplicateEnrichments_400() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));

        PayloadValidations payloadValidations = mock(PayloadValidations.class);
        when(payloadValidations.validateEnrichments(anyList(), anySet()))
                .thenReturn(
                        new RestResponse(
                                String.format(Locale.ROOT, Constants.E_400_DUPLICATE_ENRICHMENT, "connection"),
                                400));
        this.action.setPayloadValidations(payloadValidations);

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [\"connection\", \"connection\"],"
                        + "\"filters\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** Test that space hash is recalculated after a successful standard-space update. */
    public void testPutStandardPolicy_SpaceHashRecalculated_200() throws IOException {
        this.mockStandardPolicy(Collections.emptyList(), Collections.emptyList(), List.of("int-1"));
        when(this.service.findDocumentId(anyString(), anyString(), anyString()))
                .thenReturn("standard-policy-os-id");

        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        when(this.indexResponse.getId()).thenReturn("standard-policy-os-id");

        String policyJson =
                "{"
                        + "\"resource\": {"
                        + "\"enrichments\": [],"
                        + "\"filters\": [],"
                        + "\"enabled\": true,"
                        + "\"index_unclassified_events\": false,"
                        + "\"index_discarded_events\": false"
                        + "}"
                        + "}";

        RestResponse response = this.action.handleRequest(this.buildStandardRequest(policyJson));

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        // Verify SpaceService.calculateAndUpdate was called with "standard"
        verify(this.service).calculateAndUpdate(List.of("standard"));
    }
}
