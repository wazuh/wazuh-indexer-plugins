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
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.securityanalytics.action.WDeleteCustomRuleAction;
import com.wazuh.securityanalytics.action.WDeleteCustomRuleRequest;
import com.wazuh.securityanalytics.action.WDeleteRuleResponse;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
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

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        this.action = new RestDeleteRuleAction();
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

        // Mock
        this.mockSapDelete(ruleId);

        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        SearchResponse searchResponse = mock(SearchResponse.class);
        SearchHit hit = this.createIntegrationHit("integration-1", "other-rule", ruleId);
        SearchHits searchHits =
                new SearchHits(new SearchHit[] {hit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);

        when(searchResponse.getHits()).thenReturn(searchHits);
        when(searchFuture.actionGet()).thenReturn(searchResponse);
        doReturn(searchFuture).when(this.client).search(any(SearchRequest.class));

        this.mockIndexAndUpdate();

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.OK, response.status());

        verify(this.client)
                .execute(eq(WDeleteCustomRuleAction.INSTANCE), any(WDeleteCustomRuleRequest.class));
        verify(this.client).index(any(IndexRequest.class));
        verify(this.client).delete(any(DeleteRequest.class));
    }

    /**
     * Tests checks that if a rule is present in two integrations or more, it is deleted from all of
     * them and later deleted from the rules index.
     */
    public void testDeleteRule_TwoIntegrations() throws IOException {
        // Arrange
        String ruleId = "target-rule-id";

        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        this.mockSapDelete(ruleId);

        // Mock
        SearchHit hit1 = this.createIntegrationHit("int-1", "rule-A", ruleId);
        SearchHit hit2 = this.createIntegrationHit("int-2", ruleId, "rule-B");
        this.mockSearchResponse(new SearchHit[] {hit1, hit2});

        this.mockIndexAndUpdate();

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.OK, response.status());

        verify(this.client, times(2)).index(any(IndexRequest.class));
        verify(this.client).delete(any(DeleteRequest.class));
    }

    /**
     * This test checks that if the integration that the rule is part of contains an array of rules
     * the rule is correctly deleted without modifying the rest of the rules from the array.
     */
    public void testDeleteRule_IntegrationArrayWithRules() throws IOException {
        // Arrange
        String ruleId = "target-rule-id";

        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        this.mockSapDelete(ruleId);

        // Mock
        SearchHit hit = this.createIntegrationHit("int-many", "r1", "r2", ruleId, "r3", "r4");
        this.mockSearchResponse(new SearchHit[] {hit});

        this.mockIndexAndUpdate();

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.OK, response.status());

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        Map<String, Object> source = captor.getValue().sourceAsMap();
        Map<String, Object> doc = (Map<String, Object>) source.get("document");
        List<String> rules = (List<String>) doc.get("rules");

        assertEquals(4, rules.size());
        assertFalse(rules.contains(ruleId));
        assertTrue(rules.containsAll(Arrays.asList("r1", "r2", "r3", "r4")));
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when the rule
     * has not been deleted (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteRule400_MissingId() throws IOException {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        BytesRestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.BAD_REQUEST, response.status());
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule500() throws IOException {
        // Arrange
        String ruleId = "valid-id";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        // Mock
        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        SearchResponse searchResponse = mock(SearchResponse.class);
        when(searchResponse.getHits()).thenReturn(SearchHits.empty());
        when(searchFuture.actionGet()).thenReturn(searchResponse);
        doReturn(searchFuture).when(this.client).search(any(SearchRequest.class));

        ActionFuture<DeleteResponse> failureFuture = mock(ActionFuture.class);
        when(failureFuture.actionGet()).thenThrow(new RuntimeException("Simulated error"));
        doReturn(failureFuture).when(this.client).delete(any(DeleteRequest.class));

        // Act
        BytesRestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
    }

    /**
     * Mocks the successful execution of the Security Analytics Plugin (SAP) delete rule action.
     *
     * @param ruleId The ID of the rule expected to be deleted.
     */
    private void mockSapDelete(String ruleId) {
        ActionFuture<WDeleteRuleResponse> sapFuture = mock(ActionFuture.class);
        when(sapFuture.actionGet()).thenReturn(new WDeleteRuleResponse(ruleId, 1L, RestStatus.OK));
        doReturn(sapFuture)
                .when(this.client)
                .execute(eq(WDeleteCustomRuleAction.INSTANCE), any(WDeleteCustomRuleRequest.class));
    }

    /**
     * Mocks the client search response with the provided hits.
     *
     * @param hits The array of {@link SearchHit} objects to include in the search response.
     */
    private void mockSearchResponse(SearchHit[] hits) {
        ActionFuture<SearchResponse> searchFuture = mock(ActionFuture.class);
        SearchResponse searchResponse = mock(SearchResponse.class);
        SearchHits searchHits =
                new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f);

        when(searchResponse.getHits()).thenReturn(searchHits);
        when(searchFuture.actionGet()).thenReturn(searchResponse);
        doReturn(searchFuture).when(this.client).search(any(SearchRequest.class));
    }

    /**
     * Mocks the client index and delete operations. Configures the client to return valid futures for
     * both {@code index()} and {@code delete()} calls.
     */
    private void mockIndexAndUpdate() {
        ActionFuture<IndexResponse> updateFuture = mock(ActionFuture.class);
        doReturn(updateFuture).when(this.client).index(any(IndexRequest.class));

        ActionFuture<DeleteResponse> deleteFuture = mock(ActionFuture.class);
        when(deleteFuture.actionGet()).thenReturn(mock(DeleteResponse.class));
        doReturn(deleteFuture).when(this.client).delete(any(DeleteRequest.class));
    }

    /**
     * Creates a {@link SearchHit} representing an integration document with the specified rules.
     *
     * @param id The document ID for the integration.
     * @param rules A variable list of rule IDs to include in the integration's "rules" field.
     * @return A {@link SearchHit} populated with the document source.
     * @throws IOException If building the XContent source fails.
     */
    private SearchHit createIntegrationHit(String id, String... rules) throws IOException {
        SearchHit hit = new SearchHit(1, id, null, null);

        Map<String, Object> doc = new HashMap<>();
        doc.put("rules", new ArrayList<>(Arrays.asList(rules)));
        Map<String, Object> source = new HashMap<>();
        source.put("document", doc);

        hit.sourceRef(BytesReference.bytes(XContentFactory.jsonBuilder().map(source)));
        return hit;
    }
}
