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
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
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
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

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
    private SpaceService policyHashService;

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
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        this.securityAnalyticsService = mock(SecurityAnalyticsService.class);
        this.policyHashService = mock(SpaceService.class);

        this.action = spy(new RestDeleteRuleAction());
        this.action.setSecurityAnalyticsService(this.securityAnalyticsService);
        this.action.setPolicyHashService(this.policyHashService);
        this.action.setIntegrationService(mock(IntegrationService.class));
    }

    private void mockRuleInSpace(String id, String space, boolean exists) {
        when(this.client.admin().indices().prepareExists(anyString()).get().isExists())
                .thenReturn(true);
        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(exists);
        if (exists) {
            Map<String, Object> source = new HashMap<>();
            source.put(Constants.KEY_SPACE, Map.of(Constants.KEY_NAME, space));
            source.put(Constants.KEY_DOCUMENT, Map.of(Constants.KEY_ID, id));
            when(response.getSourceAsMap()).thenReturn(source);
            when(response.getSourceAsString())
                    .thenReturn(
                            "{\"document\":{\"id\":\"" + id + "\"},\"space\":{\"name\":\"" + space + "\"}}");
        }
        GetRequestBuilder getBuilder = mock(GetRequestBuilder.class, Answers.RETURNS_SELF);
        when(this.client.prepareGet(anyString(), eq(id))).thenReturn(getBuilder);
        when(getBuilder.get()).thenReturn(response);
    }

    private void mockUnlinkSearch() {
        SearchResponse searchResponse = mock(SearchResponse.class);
        SearchHits searchHits =
                new SearchHits(new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 0.0f);
        when(searchResponse.getHits()).thenReturn(searchHits);
        PlainActionFuture<SearchResponse> searchFuture = PlainActionFuture.newFuture();
        searchFuture.onResponse(searchResponse);
        when(this.client.search(any(SearchRequest.class))).thenReturn(searchFuture);
    }

    /**
     * Test the {@link RestDeleteRuleAction#executeRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule200() throws IOException {
        // Arrange
        String ruleId = "1b5a5cfb-a5fc-4db7-b5cc-bf9093a04121";

        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        // Mock
        this.mockRuleInSpace(ruleId, "draft", true);
        this.mockUnlinkSearch();

        // Act
        RestResponse response = this.action.executeRequest(request, this.client);

        // Assert
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals(ruleId, response.getMessage());
        verify(this.securityAnalyticsService).deleteRule(ruleId, false);
        verify(this.client).delete(any(DeleteRequest.class), any());

        // Verify policy hash recalculation
        verify(this.policyHashService).calculateAndUpdate(any());
    }

    /**
     * Test the {@link RestDeleteRuleAction#executeRequest(RestRequest, Client)} method when the rule
     * ID is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule400_MissingId() throws IOException {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();
        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestDeleteRuleAction#executeRequest(RestRequest, Client)} method when the rule
     * ID format is invalid. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule400_InvalidUUID() throws IOException {
        String invalidId = "not@valid#uuid";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", invalidId))
                        .build();
        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestDeleteRuleAction#executeRequest(RestRequest, Client)} method when the rule
     * is not found. The expected response is: {404, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule404_NotFound() throws IOException {
        String ruleId = "missing-id";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        this.mockRuleInSpace(ruleId, "draft", false);
        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.NOT_FOUND.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestDeleteRuleAction#executeRequest(RestRequest, Client)} method when the rule
     * is not in the draft space. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule400_NotInDraft() throws IOException {
        // Arrange
        String ruleId = "prod-id";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        // Mock
        this.mockRuleInSpace(ruleId, "standard", true);

        // Act
        RestResponse response = this.action.executeRequest(request, this.client);

        // Assert
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("is not in draft space"));
    }

    /**
     * Test the {@link RestDeleteRuleAction#executeRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule500_UnexpectedError() throws IOException {
        String ruleId = "error-id";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        when(this.client.admin().indices().prepareExists(anyString()))
                .thenThrow(new RuntimeException("Simulated failure"));

        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }
}
