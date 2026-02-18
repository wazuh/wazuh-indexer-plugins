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
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;
import org.junit.Assert;
import org.junit.Before;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestPutKvdbAction} class. This test suite validates the REST API
 * endpoint responsible for updating new CTI Kvdbs.
 *
 * <p>Tests verify Kvdb update requests, proper handling of Kvdb data, and appropriate HTTP response
 * codes for successful Kvdb update errors.
 */
public class RestPutKvdbActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPutKvdbAction action;
    private NodeClient nodeClient;
    private PolicyHashService policyHashService;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final String KVDB_PAYLOAD =
            "{"
                    + "\"resource\": {"
                    + "  \"title\": \"Example KVDB\","
                    + "  \"author\": \"Wazuh\","
                    + "  \"category\": \"cat\","
                    + "  \"description\": \"desc\","
                    + "  \"content\": {\"key\": \"value\"}"
                    + "}"
                    + "}";

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

        this.service = mock(EngineService.class);
        this.nodeClient = mock(NodeClient.class);
        this.policyHashService = mock(PolicyHashService.class);

        this.action = spy(new RestPutKvdbAction(this.service));
        this.action.setPolicyHashService(this.policyHashService);
    }

    /** Helper to mock KVDB existence and space verification via fluent API. */
    private void mockKvdbInSpace(String id, String space, boolean exists) {
        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(exists);
        if (exists) {
            Map<String, Object> source =
                    Map.of(
                            Constants.KEY_SPACE, Map.of(Constants.KEY_NAME, space),
                            Constants.KEY_DOCUMENT, Map.of(Constants.KEY_DATE, "2021-01-01"));
            when(response.getSourceAsMap()).thenReturn(source);
            try {
                when(response.getSourceAsString()).thenReturn(mapper.writeValueAsString(source));
            } catch (Exception ignored) {
            }
        }

        GetRequestBuilder builder = mock(GetRequestBuilder.class);
        when(builder.setFetchSource(anyBoolean())).thenReturn(builder);
        when(builder.get()).thenReturn(response);

        when(this.nodeClient.prepareGet(anyString(), eq(id))).thenReturn(builder);
    }

    /** Helper for SearchResponse since final classes/methods can be problematic. */
    private void mockSearchHits(long totalHits) {
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

    /**
     * Test successful KVDB update returns 200 OK.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutKvdbSuccess() throws Exception {
        String kvdbId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(KVDB_PAYLOAD), XContentType.JSON)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        mockKvdbInSpace(kvdbId, "draft", true);
        mockSearchHits(0);

        when(this.service.validateResource(eq(Constants.KEY_KVDB), any(JsonNode.class)))
                .thenReturn(new RestResponse("OK", 200));

        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.OK);
        PlainActionFuture<IndexResponse> future = new PlainActionFuture<>();
        future.onResponse(indexResponse);
        when(this.nodeClient.index(any(IndexRequest.class))).thenReturn(future);

        RestResponse actualResponse = this.action.executeRequest(request, this.nodeClient);

        Assert.assertEquals(RestStatus.OK.getStatus(), actualResponse.getStatus());
        Assert.assertEquals(kvdbId, actualResponse.getMessage());
        verify(this.policyHashService).calculateAndUpdate(any());
    }

    /** Test that missing KVDB ID returns 400 Bad Request. */
    public void testPutKvdbMissingIdReturns400() {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(KVDB_PAYLOAD), XContentType.JSON)
                        .build();

        RestResponse response = this.action.executeRequest(request, this.nodeClient);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /** Test that missing request body returns 400 Bad Request. */
    public void testPutKvdbNotFoundReturns404() {
        String kvdbId = "missing-uuid";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(KVDB_PAYLOAD), XContentType.JSON)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        mockKvdbInSpace(kvdbId, "draft", false);

        RestResponse response = this.action.executeRequest(request, this.nodeClient);
        Assert.assertEquals(RestStatus.NOT_FOUND.getStatus(), response.getStatus());
    }

    /** Test that null engine service returns 500 Internal Server Error. */
    public void testPutKvdbEngineUnavailableReturns500() {
        String kvdbId = "82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(KVDB_PAYLOAD), XContentType.JSON)
                        .withParams(Map.of("id", kvdbId))
                        .build();

        mockKvdbInSpace(kvdbId, "draft", true);
        mockSearchHits(0);

        when(this.service.validateResource(anyString(), any()))
                .thenThrow(new RuntimeException("Engine offline"));

        RestResponse response = this.action.executeRequest(request, this.nodeClient);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Engine offline"));
    }
}
