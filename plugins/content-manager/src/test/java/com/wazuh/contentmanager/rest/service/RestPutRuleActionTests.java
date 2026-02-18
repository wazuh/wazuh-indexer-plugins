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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchResponseSections;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for the {@link RestPutRuleAction} class. */
public class RestPutRuleActionTests extends OpenSearchTestCase {

    private RestPutRuleAction action;
    private NodeClient nodeClient;
    private SecurityAnalyticsService securityAnalyticsService;
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
        // Initialize PluginSettings with valid defaults
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.max_items_per_bulk", 25)
                        .put("plugins.content_manager.max_concurrent_bulks", 5)
                        .put("plugins.content_manager.client.timeout", 10)
                        .build();
        PluginSettings.getInstance(settings);

        this.nodeClient = mock(NodeClient.class);
        this.securityAnalyticsService = mock(SecurityAnalyticsService.class);
        SpaceService policyHashService = mock(SpaceService.class);

        this.action = spy(new RestPutRuleAction());
        this.action.setSecurityAnalyticsService(this.securityAnalyticsService);
        this.action.setPolicyHashService(policyHashService);
        this.action.setIntegrationService(mock(IntegrationService.class));
    }

    private void mockPrepareGetChain(GetResponse response, String id) {
        GetRequestBuilder builder = mock(GetRequestBuilder.class);
        when(builder.setFetchSource(anyBoolean())).thenReturn(builder);
        when(builder.get()).thenReturn(response);
        when(this.nodeClient.prepareGet(anyString(), eq(id))).thenReturn(builder);
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

        PlainActionFuture<SearchResponse> future = new PlainActionFuture<>();
        future.onResponse(searchResponse);
        when(this.nodeClient.search(any(SearchRequest.class))).thenReturn(future);
    }

    private GetResponse createMockGetResponse(String space, boolean exists) {
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(exists);
        if (exists) {
            Map<String, Object> source =
                    Map.of(
                            Constants.KEY_SPACE, Map.of(Constants.KEY_NAME, space),
                            Constants.KEY_DOCUMENT, Map.of(Constants.KEY_DATE, "2021-01-01"));
            when(getResponse.getSourceAsMap()).thenReturn(source);
            try {
                when(getResponse.getSourceAsString()).thenReturn(mapper.writeValueAsString(source));
            } catch (Exception ignored) {
            }
        }
        return getResponse;
    }

    /**
     * Test the {@link RestPutRuleAction#executeRequest(RestRequest, Client)} method when the request
     * is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException
     */
    public void testPutRule200() throws IOException {
        String ruleId = "1b5a5cfb-a5fc-4db7-b5cc-bf9093a04121";
        String jsonRule =
                "{\"resource\": {\"title\": \"Nginx Core Dump Updated\", \"author\": \"Florian\", \"description\": \"D\", \"documentation\": \"D\", \"references\": []}}";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        mockPrepareGetChain(createMockGetResponse("draft", true), ruleId);
        mockSearch(0);

        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.OK);
        PlainActionFuture<IndexResponse> indexFuture = new PlainActionFuture<>();
        indexFuture.onResponse(indexResponse);
        when(this.nodeClient.index(any(IndexRequest.class))).thenReturn(indexFuture);

        RestResponse response = this.action.executeRequest(request, this.nodeClient);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.securityAnalyticsService)
                .upsertRule(
                        any(), eq(com.wazuh.contentmanager.cti.catalog.model.Space.DRAFT), any(Method.class));
    }

    /**
     * Test the {@link RestPutRuleAction#executeRequest(RestRequest, Client)} method when the rule has
     * not been updated (mock). The expected response is: {400, RestResponse}
     */
    public void testPutRule400_MissingId() {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();
        RestResponse response = this.action.executeRequest(request, this.nodeClient);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestPutRuleAction#executeRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     */
    public void testPutRule404_NotFound() {
        String ruleId = "missing-id";
        String jsonRule = "{\"resource\": {\"title\": \"T\"}}";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        mockPrepareGetChain(createMockGetResponse("draft", false), ruleId);
        RestResponse response = this.action.executeRequest(request, this.nodeClient);
        Assert.assertEquals(RestStatus.NOT_FOUND.getStatus(), response.getStatus());
    }

    public void testPutRule500() {
        String ruleId = "error-id";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .withContent(new BytesArray("{\"resource\":{\"title\":\"T\"}}"), XContentType.JSON)
                        .build();

        when(this.nodeClient.prepareGet(anyString(), eq(ruleId)))
                .thenThrow(new RuntimeException("Crash"));
        RestResponse response = this.action.executeRequest(request, this.nodeClient);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }
}
