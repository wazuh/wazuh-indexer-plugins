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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.Collections;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestPostIntegrationAction} class. This test suite validates the REST
 * API endpoint responsible for creating new CTI Integrations.
 *
 * <p>Tests verify Integration creation requests, proper handling of Integration data, and
 * appropriate HTTP response codes for successful Integration creation and validation errors.
 */
public class RestPostIntegrationActionTests extends OpenSearchTestCase {

    private RestPostIntegrationAction action;
    private SecurityAnalyticsServiceImpl saService;
    private Client client;
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
        when(engine.validate(any())).thenReturn(new RestResponse("OK", 200));

        this.saService = mock(SecurityAnalyticsServiceImpl.class);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        this.action = spy(new RestPostIntegrationAction(engine));

        this.action.setSecurityAnalyticsService(this.saService);
        this.action.setPolicyHashService(mock(PolicyHashService.class));
    }

    /**
     * Helper to mock search behavior for both duplicate checks and policy retrieval. Uses explicit
     * matchers to avoid recursion and StackOverflowErrors.
     */
    private void mockSearchBehavior() {
        // 1. Mock Duplicate Check (Integrations Index) - Default to 0 hits
        SearchResponse dupResponse = mock(SearchResponse.class);
        when(dupResponse.getHits())
                .thenReturn(
                        new SearchHits(new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 1.0f));

        // 2. Mock Policy Retrieval (Policies Index) - Default to 1 hit
        SearchResponse policyResponse = mock(SearchResponse.class);
        String source =
                "{\"document\":{\"id\":\"p-1\",\"integrations\":[]},\"space\":{\"name\":\"draft\"},\"hash\":{\"sha256\":\"old\"}}";
        SearchHit hit = new SearchHit(0, "p-doc-id", Collections.emptyMap(), Collections.emptyMap());
        hit.sourceRef(new BytesArray(source));
        when(policyResponse.getHits())
                .thenReturn(
                        new SearchHits(
                                new SearchHit[] {hit}, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f));

        // Use argument matchers to return the correct mock based on the targeted index
        // This avoids the recursive thenAnswer calls that caused StackOverflow
        when(this.client
                        .search(
                                argThat(
                                        r ->
                                                r != null
                                                        && r.indices() != null
                                                        && r.indices().length > 0
                                                        && Constants.INDEX_POLICIES.equals(r.indices()[0])))
                        .actionGet())
                .thenReturn(policyResponse);
        when(this.client
                        .search(
                                argThat(
                                        r ->
                                                r != null
                                                        && r.indices() != null
                                                        && r.indices().length > 0
                                                        && Constants.INDEX_INTEGRATIONS.equals(r.indices()[0])))
                        .actionGet())
                .thenReturn(dupResponse);

        // Success mocks for futures
        PlainActionFuture<SearchResponse> pFuture = PlainActionFuture.newFuture();
        pFuture.onResponse(policyResponse);
        when(this.client.search(
                        argThat(
                                r ->
                                        r != null
                                                && r.indices() != null
                                                && r.indices().length > 0
                                                && Constants.INDEX_POLICIES.equals(r.indices()[0]))))
                .thenReturn(pFuture);

        PlainActionFuture<SearchResponse> dFuture = PlainActionFuture.newFuture();
        dFuture.onResponse(dupResponse);
        when(this.client.search(
                        argThat(
                                r ->
                                        r != null
                                                && r.indices() != null
                                                && r.indices().length > 0
                                                && Constants.INDEX_INTEGRATIONS.equals(r.indices()[0]))))
                .thenReturn(dFuture);

        // Success indexing mock
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.CREATED);
        PlainActionFuture<IndexResponse> iFuture = PlainActionFuture.newFuture();
        iFuture.onResponse(indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(iFuture);
    }

    /**
     * Test the {@link RestPostIntegrationAction#executeRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {201, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration201_success() throws IOException {
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        this.mockSearchBehavior();

        String jsonPayload =
                "{\"resource\": {\"author\": \"Wazuh\", \"category\": \"cloud\", \"title\": \"aws-fargate\"}}";
        when(request.content()).thenReturn(new BytesArray(jsonPayload));

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());
        verify(this.saService).upsertIntegration(any(), any(), any());
    }

    /**
     * Test the {@link RestPostIntegrationAction#executeRequest(RestRequest, Client)} method when the
     * payload contains an ID. The ID should be ignored and a new one generated. The expected response
     * is: {201, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegrationWithIdIsIgnored() throws IOException {
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        this.mockSearchBehavior();

        String jsonPayload =
                "{\"resource\":{\"id\":\"fake-id\",\"title\":\"T\",\"author\":\"A\",\"category\":\"C\"}}";
        when(request.content()).thenReturn(new BytesArray(jsonPayload));

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());
        // Verify the original ID in payload was overwritten
        Assert.assertNotEquals("fake-id", actualResponse.getMessage());
    }

    /**
     * Test the {@link RestPostIntegrationAction#executeRequest(RestRequest, Client)} method when no
     * content is provided. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration400_noContent() throws IOException {
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(false);

        RestResponse actualResponse = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
    }

    /**
     * Test the {@link RestPostIntegrationAction#executeRequest(RestRequest, Client)} method when
     * mandatory fields are missing. The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration_missingMandatoryFields() throws IOException {
        String basePayload =
                "{\"resource\": {\"title\": \"T\", \"author\": \"A\", \"category\": \"C\"}}";
        String[] fields = {"title", "author", "category"};

        for (String field : fields) {
            ObjectNode root = (ObjectNode) this.mapper.readTree(basePayload);
            ((ObjectNode) root.get("resource")).remove(field);
            RestRequest request = mock(RestRequest.class);
            when(request.hasContent()).thenReturn(true);
            when(request.content()).thenReturn(new BytesArray(root.toString()));

            RestResponse response = this.action.executeRequest(request, this.client);
            Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
            Assert.assertTrue(response.getMessage().contains("Missing [" + field + "]"));
        }
    }

    /**
     * Test the {@link RestPostIntegrationAction#executeRequest(RestRequest, Client)} method when the
     * payload contains ignored fields like 'date'. These are now allowed but skipped. The expected
     * response is: {201, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration_additionalFieldsAreIgnored() throws IOException {
        String basePayload =
                "{\"resource\": {\"title\": \"T\", \"author\": \"A\", \"category\": \"C\"}}";
        ObjectNode root = (ObjectNode) this.mapper.readTree(basePayload);
        ((ObjectNode) root.get("resource")).put("date", "2020-01-01");

        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(root.toString()));

        this.mockSearchBehavior();

        RestResponse response = this.action.executeRequest(request, this.client);
        Assert.assertEquals(RestStatus.CREATED.getStatus(), response.getStatus());
    }
}
