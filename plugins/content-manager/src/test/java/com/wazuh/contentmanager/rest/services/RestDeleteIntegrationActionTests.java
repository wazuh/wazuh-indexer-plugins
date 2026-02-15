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

import com.fasterxml.jackson.databind.ObjectMapper;

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
import java.util.List;
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
 * Unit tests for the {@link RestDeleteIntegrationAction} class. This test suite validates the REST
 * API endpoint responsible for deleting CTI Integrations from the draft space.
 *
 * <p>Tests verify Integration delete requests, proper handling of space validation, and appropriate
 * HTTP response codes for successful deletions and validation errors.
 */
public class RestDeleteIntegrationActionTests extends OpenSearchTestCase {

    private RestDeleteIntegrationAction action;
    private SecurityAnalyticsServiceImpl saService;
    private Client client;
    private static final String INTEGRATION_ID = "7e87cbde-8e82-41fc-b6ad-29ae789d2e32";
    private final ObjectMapper mapper = new ObjectMapper();

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
        this.saService = mock(SecurityAnalyticsServiceImpl.class);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);

        this.action = spy(new RestDeleteIntegrationAction(engine));
        this.action.setSecurityAnalyticsService(this.saService);
        this.action.setPolicyHashService(mock(PolicyHashService.class));
    }

    /** Helper method to mock an integration existence, space, and dependent resources. */
    private void mockIntegrationInSpace(
            String id, String space, boolean exists, Map<String, List<String>> resources) {
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);

        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(exists);

        if (exists) {
            Map<String, Object> source = new HashMap<>();
            source.put(Constants.KEY_SPACE, Map.of(Constants.KEY_NAME, space));
            Map<String, Object> document = new HashMap<>();
            document.put(Constants.KEY_ID, id);
            if (resources != null) {
                document.putAll(resources);
            }
            source.put(Constants.KEY_DOCUMENT, document);

            when(response.getSourceAsMap()).thenReturn(source);
            try {
                when(response.getSourceAsString()).thenReturn(this.mapper.writeValueAsString(source));
            } catch (Exception e) {
                // Ignore
            }
        }

        GetRequestBuilder getBuilder = mock(GetRequestBuilder.class, Answers.RETURNS_SELF);
        when(this.client.prepareGet(anyString(), eq(id))).thenReturn(getBuilder);
        when(getBuilder.get()).thenReturn(response);
    }

    /** Helper to mock draft policy search results for unlinking. */
    private void mockDraftPolicySearch(boolean found) {
        SearchResponse searchResponse = mock(SearchResponse.class);
        SearchHit[] hits = new SearchHit[0];

        if (found) {
            String source =
                    "{\"document\":{\"id\":\"p-1\",\"integrations\":[\""
                            + INTEGRATION_ID
                            + "\"]},\"space\":{\"name\":\"draft\"},\"hash\":{\"sha256\":\"old\"}}";
            SearchHit hit = new SearchHit(0, "p-doc-id", Collections.emptyMap(), Collections.emptyMap());
            hit.sourceRef(new BytesArray(source));
            hits = new SearchHit[] {hit};
        }

        SearchHits searchHits =
                new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f);
        when(searchResponse.getHits()).thenReturn(searchHits);

        PlainActionFuture<SearchResponse> future = PlainActionFuture.newFuture();
        future.onResponse(searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(future);

        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.OK);
        PlainActionFuture<IndexResponse> indexFuture = PlainActionFuture.newFuture();
        indexFuture.onResponse(indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(indexFuture);
    }

    /**
     * Helper method to build a FakeRestRequest with given ID parameter.
     *
     * @param integrationId The integration ID (null for no ID parameter)
     * @return A FakeRestRequest
     */
    private RestRequest buildRequest(String integrationId) {
        FakeRestRequest.Builder builder = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY);
        if (integrationId != null) {
            builder.withParams(Map.of("id", integrationId));
        }
        return builder.build();
    }

    /**
     * Test the {@link RestDeleteIntegrationAction#executeRequest(RestRequest, Client)} method when
     * the request is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration200_success() throws IOException {
        RestRequest request = this.buildRequest(INTEGRATION_ID);
        this.mockIntegrationInSpace(INTEGRATION_ID, "draft", true, null);
        this.mockDraftPolicySearch(true);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(INTEGRATION_ID, actualResponse.getMessage());
        verify(this.saService).deleteIntegration(INTEGRATION_ID);
        verify(this.client).delete(any(DeleteRequest.class), any());
    }

    /**
     * Test the {@link RestDeleteIntegrationAction#executeRequest(RestRequest, Client)} method when
     * the integration does not exist. The expected response is: {404, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration404_integrationNotFound() throws IOException {
        RestRequest request = this.buildRequest(INTEGRATION_ID);
        this.mockIntegrationInSpace(INTEGRATION_ID, "draft", false, null);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.NOT_FOUND.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestDeleteIntegrationAction#executeRequest(RestRequest, Client)} method when
     * the integration is not in the draft space. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration400_cannotDeleteNonDraftSpace() throws IOException {
        RestRequest request = this.buildRequest(INTEGRATION_ID);
        this.mockIntegrationInSpace(INTEGRATION_ID, "standard", true, null);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestDeleteIntegrationAction#executeRequest(RestRequest, Client)} method when
     * the ID is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration400_missingIdInPath() throws IOException {
        RestRequest request = this.buildRequest(null);
        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestDeleteIntegrationAction#executeRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration500_unexpectedError() throws IOException {
        RestRequest request = this.buildRequest(INTEGRATION_ID);
        when(this.client.admin()).thenThrow(new RuntimeException("OpenSearch Failure"));

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestDeleteIntegrationAction#executeRequest(RestRequest, Client)} method when
     * the integration has decoders attached. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration400_hasDecoders() throws IOException {
        RestRequest request = this.buildRequest(INTEGRATION_ID);
        this.mockIntegrationInSpace(
                INTEGRATION_ID, "draft", true, Map.of(Constants.KEY_DECODERS, List.of("d1")));

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("decoders"));
    }

    /**
     * Test the {@link RestDeleteIntegrationAction#executeRequest(RestRequest, Client)} method when
     * the integration has rules attached. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration400_hasRules() throws IOException {
        RestRequest request = this.buildRequest(INTEGRATION_ID);
        this.mockIntegrationInSpace(
                INTEGRATION_ID, "draft", true, Map.of(Constants.KEY_RULES, List.of("r1")));

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("rules"));
    }

    /**
     * Test the {@link RestDeleteIntegrationAction#executeRequest(RestRequest, Client)} method when
     * the integration has kvdbs attached. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration400_hasKvdbs() throws IOException {
        RestRequest request = this.buildRequest(INTEGRATION_ID);
        this.mockIntegrationInSpace(
                INTEGRATION_ID, "draft", true, Map.of(Constants.KEY_KVDBS, List.of("k1")));

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("kvdbs"));
    }
}
