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

import java.util.Collections;

import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class RestPostFilterActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPostFilterAction action;
    private Client client;

    // spotless:off
    private static final String FILTER_PAYLOAD = """
        {
          "space": "standard",
          "resource": {
            "name": "filter/prefilter/0",
            "enabled": true,
            "metadata": {
              "description": "Default filter to allow all events (for default ruleset)",
              "author": {
                "email": "info@wazuh.com",
                "name": "Wazuh, Inc.",
                "url": "https://wazuh.com"
              }
            },
            "check": "$host.os.platform == 'ubuntu'",
            "type": "pre-filter"
          }
        }
        """;


    private static final String FILTER_PAYLOAD_WITH_ID = """
        {
          "space": "draft",
          "resource": {
            "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
            "name": "filter/prefilter/0",
            "enabled": true,
            "metadata": {
              "description": "Default filter to allow all events (for default ruleset)",
              "author": {
                "email": "info@wazuh.com",
                "name": "Wazuh, Inc.",
                "url": "https://wazuh.com"
              }
            },
            "check": "$host.os.platform == 'ubuntu'",
            "type": "pre-filter"
          }
        }
        """;
    // spotless:on

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
        this.action = spy(new RestPostFilterAction(this.service));

        this.action.setSecurityAnalyticsService(mock(SecurityAnalyticsServiceImpl.class));
        this.action.setPolicyHashService(mock(SpaceService.class));
    }

    /** Helper to mock dependency results for indexing and linking. */
    private void mockDependencySuccess() {
        // Mock search response for policy queries
        SearchResponse policyResponse = mock(SearchResponse.class);

        // Create a proper source JSON string that ContentIndex.searchByQuery expects
        // This structure matches what REST API returns for a policy document
        String policyJson =
                "{\"space\":{\"name\":\"draft\"},\"id\":\"policy-1\",\"document\":{\"id\":\"policy-1\",\"filters\":[]},\"hash\":{\"sha256\":\"initial-hash\"}}";

        // Create SearchHit array with proper configuration
        SearchHit hit = new SearchHit(0, "policy-1", Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(new BytesArray(policyJson));

        SearchHit[] searchHits = new SearchHit[] {hit};
        when(policyResponse.getHits())
                .thenReturn(
                        new SearchHits(searchHits, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f));

        PlainActionFuture<SearchResponse> pFuture = PlainActionFuture.newFuture();
        pFuture.onResponse(policyResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(pFuture);

        // Mock index response for document creation
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.CREATED);
        PlainActionFuture<IndexResponse> iFuture = PlainActionFuture.newFuture();
        iFuture.onResponse(indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(iFuture);

        // Mock SpaceService calculateAndUpdate to prevent NPE
        SpaceService spaceService = this.action.getPolicyHashService();
        doNothing().when(spaceService).calculateAndUpdate(any());
    }

    /**
     * Test the {@link RestPostFilterAction#executeRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {201, RestResponse}
     */
    public void testPostFilterSuccess() {
        RestRequest request = this.buildRequest(FILTER_PAYLOAD);
        RestResponse engineResponse = new RestResponse("{\"status\": \"OK\"}", 200);
        when(this.service.validateResource(eq(Constants.KEY_FILTER), any(JsonNode.class)))
                .thenReturn(engineResponse);
        this.mockDependencySuccess();

        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());
        Assert.assertNotNull(actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPostFilterAction#executeRequest(RestRequest, Client)} method when the
     * payload contains an ID. The ID should be ignored and a new one generated. The expected response
     * is: {400, RestResponse}
     */
    public void testPostFilterWithIdIsIgnored() {
        RestRequest request = this.buildRequest(FILTER_PAYLOAD_WITH_ID);
        RestResponse engineResponse = new RestResponse("{\"status\": \"OK\"}", 200);
        when(this.service.validateResource(eq(Constants.KEY_FILTER), any(JsonNode.class)))
                .thenReturn(engineResponse);
        this.mockDependencySuccess();

        RestResponse actualResponse = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestPostFilterAction#executeRequest(RestRequest, Client)} method when the
     * engine service is not initialized. The expected response is: {500, RestResponse}
     */
    public void testPostFilterEngineUnavailableReturns500() {
        this.action = spy(new RestPostFilterAction(null));
        // Must re-set services because spy created a new object
        this.action.setSecurityAnalyticsService(mock(SecurityAnalyticsServiceImpl.class));
        this.action.setPolicyHashService(mock(SpaceService.class));

        RestRequest request = this.buildRequest(FILTER_PAYLOAD);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());
        Assert.assertTrue(actualResponse.getMessage().contains("Internal Server Error."));
    }

    /**
     * Test the {@link RestPostFilterAction#executeRequest(RestRequest, Client)} method when the
     * request body is missing. The expected response is: {400, RestResponse}
     */
    public void testPostFilterMissingBodyReturns400() {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();
        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    private RestRequest buildRequest(String payload) {
        return new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withContent(new BytesArray(payload), XContentType.JSON)
                .build();
    }
}
