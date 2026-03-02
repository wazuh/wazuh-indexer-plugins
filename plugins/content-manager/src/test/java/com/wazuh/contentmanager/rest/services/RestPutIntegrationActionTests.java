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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchResponseSections;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;
import org.junit.Before;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestPutIntegrationAction} class. This test suite validates the REST API
 * endpoint responsible for updating existing CTI Integrations.
 *
 * <p>Tests verify Integration update requests, proper handling of Integration data, and appropriate
 * HTTP response codes for successful Integration updates and validation errors.
 */
public class RestPutIntegrationActionTests extends OpenSearchTestCase {

    private EngineService engine;
    private RestPutIntegrationAction action;
    private SecurityAnalyticsServiceImpl saService;
    private NodeClient nodeClient;
    private static final String INTEGRATION_ID = "7e87cbde-8e82-41fc-b6ad-29ae789d2e32";
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.max_items_per_bulk", 25)
                        .put("plugins.content_manager.max_concurrent_bulks", 5)
                        .put("plugins.content_manager.client.timeout", 10)
                        .build();
        PluginSettings.getInstance(settings);

        this.engine = mock(EngineService.class);
        this.saService = mock(SecurityAnalyticsServiceImpl.class);
        this.nodeClient = mock(NodeClient.class);
        this.action = spy(new RestPutIntegrationAction(this.engine));
    }

    /**
     * Helper method to create a mock GetResponse for an existing draft integration.
     *
     * @param spaceName The space name ("draft" or "standard")
     * @return A mock GetResponse
     */
    private GetResponse createMockGetResponse(String spaceName, boolean exists, String date) {
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(exists);
        if (exists) {
            Map<String, Object> sourceMap = new HashMap<>();
            sourceMap.put("space", Map.of("name", spaceName));
            Map<String, Object> documentMap = new HashMap<>();
            documentMap.put("id", INTEGRATION_ID);
            documentMap.put("title", "aws-fargate");
            documentMap.put("author", "Wazuh Inc.");
            documentMap.put("category", "cloud-services");
            documentMap.put("description", "Desc");
            documentMap.put("documentation", "Docs");
            documentMap.put("references", List.of("https://wazuh.com"));
            documentMap.put("enabled", true);
            documentMap.put("decoders", List.of("1cb80fdb-7209-4b96-8bd1-ec15864d0f35"));
            documentMap.put("rules", List.of());
            documentMap.put("kvdbs", List.of());
            if (date != null) documentMap.put("date", date);

            sourceMap.put("document", documentMap);
            when(getResponse.getSourceAsMap()).thenReturn(sourceMap);
            try {
                when(getResponse.getSourceAsString()).thenReturn(mapper.writeValueAsString(sourceMap));
            } catch (Exception ignored) {
            }
        }
        return getResponse;
    }

    /**
     * Helper method to build a FakeRestRequest with given payload and ID.
     *
     * @param payload The JSON payload string (null for no content)
     * @param integrationId The integration ID (null for no ID parameter)
     * @return A FakeRestRequest
     */
    private RestRequest buildRequest(String payload, String integrationId) {
        FakeRestRequest.Builder builder = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY);
        if (payload != null) builder.withContent(new BytesArray(payload), XContentType.JSON);
        if (integrationId != null) builder.withParams(Map.of("id", integrationId));
        return builder.build();
    }

    private void mockPrepareGetChain(GetResponse response) {
        GetRequestBuilder builder = mock(GetRequestBuilder.class);
        when(builder.setFetchSource(anyBoolean())).thenReturn(builder);
        when(builder.get()).thenReturn(response);
        when(this.nodeClient.prepareGet(anyString(), anyString())).thenReturn(builder);
    }

    private void mockSearch(long totalHits) {
        SearchHits hits =
                new SearchHits(
                        new SearchHit[0], new TotalHits(totalHits, TotalHits.Relation.EQUAL_TO), 0.0f);
        SearchResponseSections sections =
                new SearchResponseSections(hits, null, null, false, null, null, 1);
        SearchResponse searchResponse =
                new SearchResponse(
                        sections,
                        null,
                        1,
                        1,
                        0,
                        1,
                        ShardSearchFailure.EMPTY_ARRAY,
                        SearchResponse.Clusters.EMPTY);

        org.opensearch.action.support.PlainActionFuture<SearchResponse> future =
                new org.opensearch.action.support.PlainActionFuture<>();
        future.onResponse(searchResponse);
        when(this.nodeClient.search(any(SearchRequest.class))).thenReturn(future);
    }

    private void mockIndexResponse(RestStatus status) {
        IndexResponse response = mock(IndexResponse.class);
        when(response.status()).thenReturn(status);
        org.opensearch.action.support.PlainActionFuture<IndexResponse> future =
                new org.opensearch.action.support.PlainActionFuture<>();
        future.onResponse(response);
        when(this.nodeClient.index(any(IndexRequest.class))).thenReturn(future);
    }

    private void setupDefaultMocks(String space, boolean exists) {
        mockPrepareGetChain(createMockGetResponse(space, exists, null));
        mockSearch(0);
        when(this.engine.validate(any())).thenReturn(new RestResponse("{\"status\": \"OK\"}", 200));
        mockIndexResponse(RestStatus.OK);
        this.action.setSecurityAnalyticsService(this.saService);
        this.action.setPolicyHashService(mock(PolicyHashService.class));
    }

    private String getValidPayload() {
        // spotless:off
        return """
            {
                "resource": {
                    "title": "aws-fargate",
                    "author": "Wazuh Inc.",
                    "category": "cloud-services",
                    "description": "Desc",
                    "documentation": "Docs",
                    "references": ["https://wazuh.com"],
                    "decoders": ["1cb80fdb-7209-4b96-8bd1-ec15864d0f35"],
                    "rules": [],
                    "kvdbs": []
                }
            }
            """;
        // spotless:on
    }

    /**
     * If the update succeeds, return a 200 response.
     *
     * <p>Covered test cases (after update):
     *
     * <ul>
     *   <li>A 200 OK response is returned.
     *   <li>Updated integration contains a "space.name" field containing "draft"
     *   <li>Updated integration contains a date (with the current date)
     *   <li>Updated integration contains a hash
     *   <li>The draft policy's hash is updated
     * </ul>
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration200_success() throws IOException {
        setupDefaultMocks("draft", true);
        RestRequest request = this.buildRequest(getValidPayload(), INTEGRATION_ID);
        RestResponse actualResponse = this.action.executeRequest(request, this.nodeClient);

        assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        assertEquals(INTEGRATION_ID, actualResponse.getMessage());
    }

    /**
     * Request with an ID in the payload that gets ignored
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration_idInBodyIsIgnored() throws IOException {
        setupDefaultMocks("draft", true);
        String payload =
                getValidPayload()
                        .replace(
                                "\"title\": \"aws-fargate\"",
                                "\"title\": \"aws-fargate\", \"id\": \"ignored-payload-id\"");
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        RestResponse actualResponse = this.action.executeRequest(request, nodeClient);
        assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        assertEquals(INTEGRATION_ID, actualResponse.getMessage());
    }

    /**
     * Request without content
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration400_noContent() throws IOException {
        RestRequest request = this.buildRequest(null, INTEGRATION_ID);
        RestResponse actualResponse = this.action.executeRequest(request, nodeClient);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Integration does not exist
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration404_integrationNotFound() throws IOException {
        setupDefaultMocks("draft", false);
        RestRequest request = this.buildRequest(getValidPayload(), INTEGRATION_ID);
        RestResponse actualResponse = this.action.executeRequest(request, nodeClient);
        assertEquals(RestStatus.NOT_FOUND.getStatus(), actualResponse.getStatus());
    }

    /**
     * If the engine does not respond, return 500
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration500_noEngineReply() throws IOException {
        setupDefaultMocks("draft", true);
        when(this.engine.validate(any())).thenThrow(new RuntimeException("Engine connection failed"));

        RestRequest request = this.buildRequest(getValidPayload(), INTEGRATION_ID);
        RestResponse actualResponse = this.action.executeRequest(request, nodeClient);
        assertEquals(500, actualResponse.getStatus());
    }

    /**
     * Failed to index CTI Integration
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration500_failedToIndexIntegration() throws IOException {
        setupDefaultMocks("draft", true);
        org.opensearch.action.support.PlainActionFuture<IndexResponse> future =
                new org.opensearch.action.support.PlainActionFuture<>();
        future.onFailure(new RuntimeException("Failure"));
        when(this.nodeClient.index(any(IndexRequest.class))).thenReturn(future);

        RestRequest request = this.buildRequest(getValidPayload(), INTEGRATION_ID);
        RestResponse actualResponse = this.action.executeRequest(request, nodeClient);
        assertEquals(500, actualResponse.getStatus());
    }

    /**
     * Cannot update integration in non-draft space
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration400_cannotUpdateNonDraftSpace() throws IOException {
        setupDefaultMocks("standard", true);
        RestRequest request = this.buildRequest(getValidPayload(), INTEGRATION_ID);
        RestResponse actualResponse = this.action.executeRequest(request, nodeClient);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        assertTrue(actualResponse.getMessage().contains("is not in draft space"));
    }

    /**
     * Missing ID in path parameter
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration400_missingIdInPath() throws IOException {
        RestRequest request = this.buildRequest(getValidPayload(), null);
        RestResponse actualResponse = this.action.executeRequest(request, nodeClient);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Unexpected error handling Integration
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration500_unexpectedError() throws IOException {
        setupDefaultMocks("draft", true);
        when(this.nodeClient.prepareGet(anyString(), anyString()))
                .thenThrow(new RuntimeException("Crash"));
        RestRequest request = this.buildRequest(getValidPayload(), INTEGRATION_ID);
        RestResponse actualResponse = this.action.executeRequest(request, nodeClient);
        assertEquals(500, actualResponse.getStatus());
    }

    /**
     * Check that the indexed field doesn't have the type field
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration_indexedDocHasNoType() throws IOException {
        setupDefaultMocks("draft", true);
        RestRequest request = buildRequest(getValidPayload(), INTEGRATION_ID);
        this.action.executeRequest(request, nodeClient);

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.nodeClient).index(captor.capture());
        assertFalse(
                "Indexed document root should not contain 'type' field",
                captor.getValue().source().utf8ToString().contains("\"type\":"));
    }

    /**
     * Checks that date is preserved but modified changes
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration_datePreservedModifiedUpdated() throws IOException {
        String originalDate = "2020-01-01T00:00:00Z";
        mockPrepareGetChain(createMockGetResponse("draft", true, originalDate));
        mockSearch(0);
        when(this.engine.validate(any())).thenReturn(new RestResponse("{\"status\": \"OK\"}", 200));
        mockIndexResponse(RestStatus.OK);
        this.action.setSecurityAnalyticsService(this.saService);
        this.action.setPolicyHashService(mock(PolicyHashService.class));

        RestRequest request = buildRequest(getValidPayload(), INTEGRATION_ID);
        this.action.executeRequest(request, nodeClient);

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.nodeClient).index(captor.capture());
        assertTrue(
                "Original creation date must be preserved in document",
                captor.getValue().source().utf8ToString().contains(originalDate));
    }

    /**
     * Checks that if the mandatory fields are missing then there is an error
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration_missingMandatoryFields() throws IOException {
        setupDefaultMocks("draft", true);
        String[] fields = {"title", "author", "category", "description", "references", "documentation"};
        for (String field : fields) {
            ObjectNode payload = (ObjectNode) mapper.readTree(getValidPayload());
            ((ObjectNode) payload.get("resource")).remove(field);
            RestRequest request = buildRequest(payload.toString(), INTEGRATION_ID);
            RestResponse response = this.action.executeRequest(request, nodeClient);
            assertEquals(
                    "Fail on missing field: " + field,
                    RestStatus.BAD_REQUEST.getStatus(),
                    response.getStatus());
        }
    }

    /**
     * Checks that if any members are added/deleted to any of the lists of resources it fails
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration_listContentModified() throws IOException {
        setupDefaultMocks("draft", true);
        ObjectNode payload = (ObjectNode) mapper.readTree(getValidPayload());
        ((ObjectNode) payload.get("resource")).putArray("decoders").add("forbidden-modification-id");
        RestRequest request = buildRequest(payload.toString(), INTEGRATION_ID);
        RestResponse response = this.action.executeRequest(request, nodeClient);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /**
     * Checks that the reorganization of the resources list is allowed and works
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration_listReordered() throws IOException {
        setupDefaultMocks("draft", true);
        RestRequest request = buildRequest(getValidPayload(), INTEGRATION_ID);
        RestResponse response = this.action.executeRequest(request, nodeClient);
        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
    }
}
