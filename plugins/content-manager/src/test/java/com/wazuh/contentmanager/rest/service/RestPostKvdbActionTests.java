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
package com.wazuh.contentmanager.rest.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.PlainActionFuture;
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
import org.opensearch.transport.client.Client;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestPostKvdbAction} class. This test suite validates the REST API
 * endpoint responsible for creating new CTI Kvdbs.
 *
 * <p>Tests verify Kvdb creation requests, proper handling of Kvdb data, and appropriate HTTP
 * response codes for successful Kvdb creation and validation errors.
 */
public class RestPostKvdbActionTests extends OpenSearchTestCase {

    private EngineService service;
    private RestPostKvdbAction action;
    private Client client;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final String KVDB_PAYLOAD =
            "{"
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"title\": \"Example KVDB\","
                    + "  \"description\": \"Example KVDB description\","
                    + "  \"author\": \"Wazuh\","
                    + "  \"content\": {\"key\": \"value\"}"
                    + "}"
                    + "}";

    private static final String KVDB_PAYLOAD_WITH_ID =
            "{"
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"id\": \"82e215c4-988a-4f64-8d15-b98b2fc03a4f\","
                    + "  \"title\": \"Example KVDB\","
                    + "  \"author\": \"Wazuh\","
                    + "  \"content\": {\"key\": \"value\"}"
                    + "}"
                    + "}";

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
        this.service = mock(EngineService.class);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        this.action = spy(new RestPostKvdbAction(this.service));

        this.action.setSecurityAnalyticsService(mock(SecurityAnalyticsServiceImpl.class));
        this.action.setPolicyHashService(mock(PolicyHashService.class));
    }

    /** Helper method to mock an integration existence and space with mutable collections. */
    private void mockIntegrationInSpace(String id, String space, boolean exists) {
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);

        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(exists);
        if (exists) {
            Map<String, Object> source = new HashMap<>();
            Map<String, Object> spaceMap = new HashMap<>();
            spaceMap.put(Constants.KEY_NAME, space);
            source.put(Constants.KEY_SPACE, spaceMap);

            Map<String, Object> document = new HashMap<>();
            document.put(Constants.KEY_ID, id);
            document.put(Constants.KEY_KVDBS, new ArrayList<String>());
            source.put(Constants.KEY_DOCUMENT, document);

            when(response.getSourceAsMap()).thenReturn(source);
            try {
                when(response.getSourceAsString()).thenReturn(this.mapper.writeValueAsString(source));
            } catch (Exception e) {
            }
        }

        GetRequestBuilder getBuilder = mock(GetRequestBuilder.class, Answers.RETURNS_SELF);
        when(this.client.prepareGet(anyString(), eq(id))).thenReturn(getBuilder);
        when(getBuilder.get()).thenReturn(response);
    }

    /** Helper to mock all required dependency successes for creation. */
    private void mockDependencySuccess() {
        this.mockIntegrationInSpace("integration-1", "draft", true);

        SearchResponse policyResponse = mock(SearchResponse.class);
        when(policyResponse.getHits())
                .thenReturn(
                        new SearchHits(new SearchHit[0], new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f));
        PlainActionFuture<SearchResponse> pFuture = PlainActionFuture.newFuture();
        pFuture.onResponse(policyResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(pFuture);

        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.CREATED);
        PlainActionFuture<IndexResponse> iFuture = PlainActionFuture.newFuture();
        iFuture.onResponse(indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(iFuture);
    }

    /**
     * Test the {@link RestPostKvdbAction#executeRequest(RestRequest, Client)} method when the request
     * is complete. The expected response is: {201, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPostKvdbSuccess() throws Exception {
        RestRequest request = this.buildRequest(KVDB_PAYLOAD);
        RestResponse engineResponse = new RestResponse("OK", 200);
        when(this.service.validateResource(eq(Constants.KEY_KVDB), any(JsonNode.class)))
                .thenReturn(engineResponse);
        this.mockDependencySuccess();

        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());
        Assert.assertNotNull(actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPostKvdbAction#executeRequest(RestRequest, Client)} method when the payload
     * contains an ID. The ID should be ignored and a new one generated. The expected response is:
     * {201, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPostKvdbWithIdIsIgnored() throws Exception {
        RestRequest request = this.buildRequest(KVDB_PAYLOAD_WITH_ID);
        RestResponse engineResponse = new RestResponse("OK", 200);
        when(this.service.validateResource(eq(Constants.KEY_KVDB), any(JsonNode.class)))
                .thenReturn(engineResponse);
        this.mockDependencySuccess();

        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());
        // Verify the original ID in payload was overwritten
        Assert.assertNotEquals("82e215c4-988a-4f64-8d15-b98b2fc03a4f", actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPostKvdbAction#executeRequest(RestRequest, Client)} method when the engine
     * service is not initialized. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostKvdbEngineUnavailableReturns500() throws IOException {
        this.action = spy(new RestPostKvdbAction(null));
        this.action.setSecurityAnalyticsService(mock(SecurityAnalyticsServiceImpl.class));
        this.action.setPolicyHashService(mock(PolicyHashService.class));

        RestRequest request = this.buildRequest(KVDB_PAYLOAD);
        this.mockIntegrationInSpace("integration-1", "draft", true);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("Internal Server Error."));
    }

    /**
     * Test the {@link RestPostKvdbAction#executeRequest(RestRequest, Client)} method when the
     * integration is not in the draft space. The expected response is: {400, RestResponse}
     *
     * @throws Exception if an error occurs during the test
     */
    public void testPostKvdbIntegrationNotInDraftReturns400() throws Exception {
        RestRequest request = this.buildRequest(KVDB_PAYLOAD);
        this.mockIntegrationInSpace("integration-1", "standard", true);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("is not in draft space"));
    }

    /**
     * Test the {@link RestPostKvdbAction#executeRequest(RestRequest, Client)} method when mandatory
     * fields are missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostKvdb_missingMandatoryFields() throws IOException {
        String[] fields = {Constants.KEY_TITLE, Constants.KEY_AUTHOR, "content"};

        for (String field : fields) {
            ObjectNode root = (ObjectNode) this.mapper.readTree(KVDB_PAYLOAD);
            ((ObjectNode) root.get(Constants.KEY_RESOURCE)).remove(field);

            RestRequest request = this.buildRequest(root.toString());
            RestResponse response = this.action.executeRequest(request, this.client);

            Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
            Assert.assertTrue(response.getMessage().contains("Missing [" + field + "]"));
        }
    }

    private RestRequest buildRequest(String payload) {
        return new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withContent(new BytesArray(payload), XContentType.JSON)
                .build();
    }
}
