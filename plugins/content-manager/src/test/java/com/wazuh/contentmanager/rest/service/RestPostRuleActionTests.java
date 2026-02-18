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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestPostRuleAction} class. This test suite validates the REST API
 * endpoint responsible for creating new CTI Rules.
 *
 * <p>Tests verify Rule creation requests, proper handling of Rule data, and appropriate HTTP
 * response codes for successful Rule creation and validation errors.
 */
public class RestPostRuleActionTests extends OpenSearchTestCase {

    private RestPostRuleAction action;
    private Client client;
    private SecurityAnalyticsService securityAnalyticsService;
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
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        this.securityAnalyticsService = mock(SecurityAnalyticsService.class);
        PolicyHashService policyHashService = mock(PolicyHashService.class);

        this.action = spy(new RestPostRuleAction());
        this.action.setSecurityAnalyticsService(this.securityAnalyticsService);
        this.action.setPolicyHashService(policyHashService);
    }

    /**
     * Helper to mock dependencies including Integration existence, Duplicate Title, and Policy
     * unlinking. Uses robust non-recursive stubbing based on targeted indices.
     */
    private void mockDependencyChecks(boolean integrationExists, boolean duplicateTitle) {
        // 1. Mock Integration existence
        GetResponse integrationResp = mock(GetResponse.class);
        when(integrationResp.isExists()).thenReturn(integrationExists);
        if (integrationExists) {
            Map<String, Object> source = new HashMap<>();
            source.put(Constants.KEY_SPACE, Map.of(Constants.KEY_NAME, "draft"));
            Map<String, Object> document = new HashMap<>();
            document.put(Constants.KEY_RULES, new ArrayList<String>());
            source.put(Constants.KEY_DOCUMENT, document);
            when(integrationResp.getSourceAsMap()).thenReturn(source);
            try {
                when(integrationResp.getSourceAsString())
                        .thenReturn(this.mapper.writeValueAsString(source));
            } catch (Exception ignored) {
            }
        }
        GetRequestBuilder getBuilder = mock(GetRequestBuilder.class, Answers.RETURNS_SELF);
        when(this.client.prepareGet(eq(Constants.INDEX_INTEGRATIONS), anyString()))
                .thenReturn(getBuilder);
        when(getBuilder.get()).thenReturn(integrationResp);

        // 2. Mock Search Responses (Policy unlinking and Duplicate title check)
        SearchResponse policyResp = mock(SearchResponse.class);
        String pSource =
                "{\"document\":{\"id\":\"p-1\",\"integrations\":[]},\"space\":{\"name\":\"draft\"},\"hash\":{\"sha256\":\"old\"}}";
        SearchHit pHit = new SearchHit(0, "p-doc-id", Collections.emptyMap(), Collections.emptyMap());
        pHit.sourceRef(new BytesArray(pSource));
        when(policyResp.getHits())
                .thenReturn(
                        new SearchHits(
                                new SearchHit[] {pHit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f));

        SearchResponse dupResp = mock(SearchResponse.class);
        long dupHits = duplicateTitle ? 1 : 0;
        when(dupResp.getHits())
                .thenReturn(
                        new SearchHits(
                                new SearchHit[0], new TotalHits(dupHits, TotalHits.Relation.EQUAL_TO), 1.0f));

        when(this.client
                        .search(
                                argThat(
                                        r ->
                                                r != null
                                                        && r.indices() != null
                                                        && r.indices().length > 0
                                                        && Constants.INDEX_POLICIES.equals(r.indices()[0])))
                        .actionGet())
                .thenReturn(policyResp);
        when(this.client
                        .search(
                                argThat(
                                        r ->
                                                r != null
                                                        && r.indices() != null
                                                        && r.indices().length > 0
                                                        && Constants.INDEX_RULES.equals(r.indices()[0])))
                        .actionGet())
                .thenReturn(dupResp);

        PlainActionFuture<SearchResponse> pFuture = PlainActionFuture.newFuture();
        pFuture.onResponse(policyResp);
        when(this.client.search(
                        argThat(
                                r ->
                                        r != null
                                                && r.indices() != null
                                                && r.indices().length > 0
                                                && Constants.INDEX_POLICIES.equals(r.indices()[0]))))
                .thenReturn(pFuture);

        PlainActionFuture<SearchResponse> dFuture = PlainActionFuture.newFuture();
        dFuture.onResponse(dupResp);
        when(this.client.search(
                        argThat(
                                r ->
                                        r != null
                                                && r.indices() != null
                                                && r.indices().length > 0
                                                && Constants.INDEX_RULES.equals(r.indices()[0]))))
                .thenReturn(dFuture);

        // 3. Mock Indexing success
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.CREATED);
        PlainActionFuture<IndexResponse> iFuture = PlainActionFuture.newFuture();
        iFuture.onResponse(indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(iFuture);
    }

    /**
     * Test the {@link RestPostRuleAction#executeRequest(RestRequest, Client)} method when the request
     * is complete. The expected response is: {201, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostRule201() throws IOException {
        String jsonRule =
                "{\"integration\": \"integration-1\", \"resource\": {\"title\": \"Rule\", \"logsource\": { \"product\": \"p\" }}}";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        this.mockDependencyChecks(true, false);

        RestResponse response = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.CREATED.getStatus(), response.getStatus());
        verify(this.securityAnalyticsService).upsertRule(any(), eq(Space.DRAFT));
    }

    /**
     * Test the {@link RestPostRuleAction#executeRequest(RestRequest, Client)} method when the rule
     * integration ID is missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostRule400_MissingIntegrationId() throws IOException {
        String jsonRule = "{\"resource\": {\"title\": \"Rule\"}}";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        RestResponse response = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains(Constants.KEY_INTEGRATION));
    }

    /**
     * Test the {@link RestPostRuleAction#executeRequest(RestRequest, Client)} method when the payload
     * contains an ID. The ID should be ignored and a new one generated. The expected response is:
     * {201, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostRule_idInPayloadIsIgnored() throws IOException {
        String jsonRule =
                "{\"integration\": \"integration-1\", \"resource\": {\"id\": \"fake-id\", \"title\": \"Rule\", \"logsource\": { \"product\": \"p\" }}}";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        this.mockDependencyChecks(true, false);

        RestResponse response = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.CREATED.getStatus(), response.getStatus());
        // Verify original ID was ignored and replaced
        Assert.assertNotEquals("fake-id", response.getMessage());
    }

    /**
     * Test the {@link RestPostRuleAction#executeRequest(RestRequest, Client)} method when the parent
     * integration is not found. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostRule400_IntegrationNotFound() throws IOException {
        String jsonRule = "{\"integration\": \"missing\", \"resource\": {\"title\": \"R\"}}";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        this.mockDependencyChecks(false, false);

        RestResponse response = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("not found"));
    }

    /**
     * Test the {@link RestPostRuleAction#executeRequest(RestRequest, Client)} method when the rule
     * title already exists. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostRule400_DuplicateTitle() throws IOException {
        String jsonRule =
                "{\"integration\": \"integration-1\", \"resource\": {\"title\": \"Existing\"}}";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        this.mockDependencyChecks(true, true);

        RestResponse response = this.action.executeRequest(request, this.client);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("already exists"));
    }

    /**
     * Test the {@link RestPostRuleAction#executeRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostRule500_UnexpectedError() throws IOException {
        String jsonRule = "{\"integration\": \"integration-1\", \"resource\": {\"title\": \"Error\"}}";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(jsonRule), XContentType.JSON)
                        .build();

        when(this.client.prepareGet(anyString(), anyString()))
                .thenThrow(new RuntimeException("Failure"));

        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }
}
