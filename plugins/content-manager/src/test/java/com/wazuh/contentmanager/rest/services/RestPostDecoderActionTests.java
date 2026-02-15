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
import com.fasterxml.jackson.databind.ObjectMapper;

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
 * Unit tests for the {@link RestPostDecoderAction} class. This test suite validates the REST API
 * endpoint responsible for creating new CTI Decoders.
 *
 * <p>Tests verify Decoder create requests, proper handling of Decoder data, and appropriate HTTP
 * response codes for successful Decoder create errors.
 */
public class RestPostDecoderActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPostDecoderAction action;
    private Client client;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final String DECODER_PAYLOAD =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"description\": \"Example decoder description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String DECODER_PAYLOAD_WITH_ID =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"id\": \"82e215c4-988a-4f64-8d15-b98b2fc03a4f\","
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"description\": \"Example decoder description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String DECODER_PAYLOAD_MISSING_INTEGRATION =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"resource\": {"
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"description\": \"Example decoder description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
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
        this.action = spy(new RestPostDecoderAction(this.service));

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
            document.put(Constants.KEY_DECODERS, new ArrayList<String>());
            source.put(Constants.KEY_DOCUMENT, document);

            when(response.getSourceAsMap()).thenReturn(source);
            try {
                when(response.getSourceAsString()).thenReturn(this.mapper.writeValueAsString(source));
            } catch (Exception ignored) {
            }
        }

        GetRequestBuilder getBuilder = mock(GetRequestBuilder.class, Answers.RETURNS_SELF);
        when(this.client.prepareGet(anyString(), eq(id))).thenReturn(getBuilder);
        when(getBuilder.get()).thenReturn(response);
    }

    /** Helper to mock dependency results for indexing and linking. */
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
     * Test the {@link RestPostDecoderAction#executeRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {201, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostDecoderSuccess() throws IOException {
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        RestResponse engineResponse = new RestResponse("{\"status\": \"OK\"}", 200);
        when(this.service.validateResource(eq(Constants.KEY_DECODER), any(JsonNode.class)))
                .thenReturn(engineResponse);
        this.mockDependencySuccess();

        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());
        Assert.assertNotNull(actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPostDecoderAction#executeRequest(RestRequest, Client)} method when the
     * payload contains an ID. The ID should be ignored and a new one generated. The expected response
     * is: {201, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostDecoderWithIdIsIgnored() throws IOException {
        RestRequest request = this.buildRequest(DECODER_PAYLOAD_WITH_ID);
        RestResponse engineResponse = new RestResponse("{\"status\": \"OK\"}", 200);
        when(this.service.validateResource(eq(Constants.KEY_DECODER), any(JsonNode.class)))
                .thenReturn(engineResponse);
        this.mockDependencySuccess();

        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());
        // Verify the original ID in payload was overwritten with a generated UUID
        Assert.assertNotEquals("82e215c4-988a-4f64-8d15-b98b2fc03a4f", actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPostDecoderAction#executeRequest(RestRequest, Client)} method when the
     * integration ID is missing from the payload. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostDecoderMissingIntegrationReturns400() throws IOException {
        RestRequest request = this.buildRequest(DECODER_PAYLOAD_MISSING_INTEGRATION);
        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains(Constants.KEY_INTEGRATION));
    }

    /**
     * Test the {@link RestPostDecoderAction#executeRequest(RestRequest, Client)} method when the
     * engine service is not initialized. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostDecoderEngineUnavailableReturns500() throws IOException {
        this.action = spy(new RestPostDecoderAction(null));
        // Must re-set services because spy created a new object
        this.action.setSecurityAnalyticsService(mock(SecurityAnalyticsServiceImpl.class));
        this.action.setPolicyHashService(mock(PolicyHashService.class));

        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        this.mockIntegrationInSpace("integration-1", "draft", true);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("Internal Server Error."));
    }

    /**
     * Test the {@link RestPostDecoderAction#executeRequest(RestRequest, Client)} method when the
     * request body is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostDecoderMissingBodyReturns400() throws IOException {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();
        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestPostDecoderAction#executeRequest(RestRequest, Client)} method when the
     * integration is not found in the index. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostDecoderIntegrationNotFoundReturns400() throws IOException {
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        this.mockIntegrationInSpace("integration-1", "draft", false);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("not found"));
    }

    /**
     * Test the {@link RestPostDecoderAction#executeRequest(RestRequest, Client)} method when the
     * integration is not in the draft space. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostDecoderIntegrationNotInDraftSpaceReturns400() throws IOException {
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        this.mockIntegrationInSpace("integration-1", "standard", true);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("is not in draft space"));
    }

    private RestRequest buildRequest(String payload) {
        return new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withContent(new BytesArray(payload), XContentType.JSON)
                .build();
    }
}
