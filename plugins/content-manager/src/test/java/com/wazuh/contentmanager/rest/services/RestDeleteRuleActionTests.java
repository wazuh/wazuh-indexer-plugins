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
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestDeleteRuleAction} class. This test suite validates the REST API
 * endpoint responsible for deleting new CTI Rules.
 *
 * <p>Tests verify Rule delete requests, proper handling of Rule data, and appropriate HTTP response
 * codes for successful Rule delete errors.
 */
public class RestDeleteRuleActionTests extends OpenSearchTestCase {

    private RestDeleteRuleAction action;
    private Client client;
    private SecurityAnalyticsService securityAnalyticsService;
    private PolicyHashService policyHashService;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(Settings.EMPTY);
        this.client = mock(Client.class);
        this.securityAnalyticsService = mock(SecurityAnalyticsService.class);
        this.policyHashService = mock(PolicyHashService.class);

        this.action = new RestDeleteRuleAction();
        this.action.setSecurityAnalyticsService(this.securityAnalyticsService);
        this.action.setPolicyHashService(this.policyHashService);
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteRule200() throws IOException {
        // Arrange
        String ruleId = "1b5a5cfb-a5fc-4db7-b5cc-bf9093a04121";

        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        // Mock client with RETURNS_DEEP_STUBS for chained calls
        this.client = mock(Client.class, RETURNS_DEEP_STUBS);

        // Mock ContentIndex.exists() - rule exists
        GetResponse existsResponse = mock(GetResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        when(this.client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
                .thenReturn(existsResponse);

        // Mock draft space validation
        GetResponse ruleGetResponse = mock(GetResponse.class);
        when(ruleGetResponse.isExists()).thenReturn(true);
        java.util.Map<String, Object> ruleSource = new java.util.HashMap<>();
        java.util.Map<String, Object> ruleSpace = new java.util.HashMap<>();
        ruleSpace.put("name", "draft");
        ruleSource.put("space", ruleSpace);
        when(ruleGetResponse.getSourceAsMap()).thenReturn(ruleSource);
        when(this.client.prepareGet(anyString(), anyString()).get()).thenReturn(ruleGetResponse);

        // Mock
        SearchResponse searchResponse = mock(SearchResponse.class);
        SearchHits searchHits =
                new SearchHits(new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 0.0f);
        when(searchResponse.getHits()).thenReturn(searchHits);
        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        when(searchFuture.actionGet()).thenReturn(searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        assertEquals(ruleId, response.getMessage());

        // Verify SAP delete was called on the SERVICE, not the client
        verify(this.securityAnalyticsService).deleteRule(ruleId);

        // Verify policy hash recalculation
        verify(this.policyHashService).calculateAndUpdate(any());
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when the rule
     * ID is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteRule400_MissingId() throws IOException {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        RestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(
                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_ID),
                response.getMessage());
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when the rule
     * ID is not a valid UUID. The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteRule400_InvalidUUID() throws IOException {
        String invalidId = "not-a-valid-uuid";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", invalidId))
                        .build();

        RestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(
                String.format(Locale.ROOT, Constants.E_400_INVALID_UUID, invalidId), response.getMessage());
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule500() throws IOException {
        // Arrange
        String ruleId = "1b5a5cfb-a5fc-4db7-b5cc-bf9093a04121";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        // Mock client to throw exception during "exists" check
        this.client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(this.client.prepareGet(anyString(), anyString()))
                .thenThrow(new RuntimeException("Unexpected error"));

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        assertEquals(Constants.E_500_INTERNAL_SERVER_ERROR, response.getMessage());
    }
}
