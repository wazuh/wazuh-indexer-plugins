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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.search.SearchRequestBuilder;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.IdsQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.securityanalytics.action.WIndexDetectorRequest;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link SecurityAnalyticsServiceImpl#buildDetectorRequest(JsonNode, boolean)},
 * verifying that {@code fetchEnabledRuleIds} builds the correct query (IDs + enabled filter) and
 * that only enabled rules are included in detectors.
 */
public class SecurityAnalyticsServiceImplTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecurityAnalyticsServiceImpl service;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private SearchRequestBuilder searchRequestBuilder;

    private static final String RULE_1 = "5312c4d3-0aa6-4690-b2d9-e8175416d889";
    private static final String RULE_2 = "d1638368-27f8-4071-a22c-7b0e4e05cbe8";
    private static final String RULE_3 = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    /** Captures the SearchSourceBuilder passed to the mock client. */
    private final ArgumentCaptor<SearchSourceBuilder> sourceCaptor =
            ArgumentCaptor.forClass(SearchSourceBuilder.class);

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.service = new SecurityAnalyticsServiceImpl(this.client);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private JsonNode integrationDoc(String... ruleIds) throws Exception {
        StringBuilder rules = new StringBuilder("[");
        for (int i = 0; i < ruleIds.length; i++) {
            if (i > 0) rules.append(",");
            rules.append("\"").append(ruleIds[i]).append("\"");
        }
        rules.append("]");
        // spotless:off
        return MAPPER.readTree(
                String.format(
                        """
                        {
                          "id": "integration-1",
                          "metadata": {"title": "Test Integration"},
                          "category": "security",
                          "rules": %s
                        }
                        """,
                        rules));
        // spotless:on
    }

    private SearchHit createHit(String id) {
        return new SearchHit(id.hashCode(), id, Collections.emptyMap(), Collections.emptyMap());
    }

    private SearchResponse createSearchResponse(SearchHit... hits) {
        SearchHits searchHits =
                new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f);
        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits()).thenReturn(searchHits);
        return response;
    }

    private SearchResponse createEmptySearchResponse() {
        SearchHits searchHits =
                new SearchHits(new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 0.0f);
        SearchResponse response = mock(SearchResponse.class);
        when(response.getHits()).thenReturn(searchHits);
        return response;
    }

    private void mockSearch(SearchResponse response) {
        when(this.client.prepareSearch(anyString())).thenReturn(this.searchRequestBuilder);
        when(this.searchRequestBuilder.setSource(sourceCaptor.capture()))
                .thenReturn(this.searchRequestBuilder);
        when(this.searchRequestBuilder.get()).thenReturn(response);
    }

    /**
     * Extracts and validates the query structure built by {@code fetchEnabledRuleIds}. Asserts that
     * the query is a BoolQuery with an IDs clause and a term filter on {@code document.enabled =
     * true}, and that source fetching is disabled.
     *
     * @param expectedIds the rule IDs that should appear in the IDs query
     */
    private void assertQueryCorrect(String... expectedIds) {
        SearchSourceBuilder captured = sourceCaptor.getValue();

        // Source fetching must be disabled (we only need _id)
        assertFalse("fetchSource should be false", captured.fetchSource().fetchSource());

        // Size must match the number of candidate IDs
        assertEquals("size must match candidate count", expectedIds.length, captured.size());

        // Top-level query must be a BoolQuery
        QueryBuilder topQuery = captured.query();
        assertNotNull("Query should not be null", topQuery);
        assertTrue(
                "Top query should be BoolQuery, got " + topQuery.getClass().getSimpleName(),
                topQuery instanceof BoolQueryBuilder);

        BoolQueryBuilder boolQuery = (BoolQueryBuilder) topQuery;
        List<QueryBuilder> musts = boolQuery.must();
        assertEquals("BoolQuery should have exactly 2 must clauses", 2, musts.size());

        // Find the IDs query and the term query among the must clauses
        IdsQueryBuilder idsQuery = null;
        TermQueryBuilder termQuery = null;
        for (QueryBuilder clause : musts) {
            if (clause instanceof IdsQueryBuilder) {
                idsQuery = (IdsQueryBuilder) clause;
            } else if (clause instanceof TermQueryBuilder) {
                termQuery = (TermQueryBuilder) clause;
            }
        }

        // Verify IDs query contains the expected rule IDs
        assertNotNull("Must contain an IDs query", idsQuery);
        Set<String> actualIds = idsQuery.ids();
        assertEquals(
                "IDs query should contain all candidate IDs", expectedIds.length, actualIds.size());
        for (String expectedId : expectedIds) {
            assertTrue("IDs query should contain " + expectedId, actualIds.contains(expectedId));
        }

        // Verify term filter on document.enabled = true
        assertNotNull("Must contain a term query", termQuery);
        assertEquals(
                "Term query field should be document.enabled",
                Constants.Q_DOCUMENT_ENABLED,
                termQuery.fieldName());
        assertEquals("Term query value should be true", true, termQuery.value());
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    /** Integration with no rules: no query executed, returns null. */
    public void testNoRulesReturnsNull() throws Exception {
        JsonNode doc = integrationDoc();
        WIndexDetectorRequest request = this.service.buildDetectorRequest(doc, true);
        assertNull("Detector should not be created when integration has no rules", request);
        // No search should have been triggered
        verify(this.client, never()).prepareSearch(anyString());
    }

    /** All rules enabled: query built correctly, all IDs returned in detector. */
    public void testAllRulesEnabled() throws Exception {
        JsonNode doc = integrationDoc(RULE_1, RULE_2);
        mockSearch(createSearchResponse(createHit(RULE_1), createHit(RULE_2)));

        WIndexDetectorRequest request = this.service.buildDetectorRequest(doc, true);

        // Verify the query was built correctly
        verify(this.client).prepareSearch(Constants.INDEX_RULES);
        assertQueryCorrect(RULE_1, RULE_2);

        // Verify all enabled rules are in the detector
        assertNotNull("Detector should be created when all rules are enabled", request);
        List<String> rules = request.getRules();
        assertEquals(2, rules.size());
        assertTrue(rules.contains(RULE_1));
        assertTrue(rules.contains(RULE_2));
    }

    /** Some rules disabled: query includes all candidates, only enabled ones in detector. */
    public void testSomeRulesDisabled() throws Exception {
        JsonNode doc = integrationDoc(RULE_1, RULE_2, RULE_3);
        // Query returns only RULE_1 and RULE_3 (RULE_2 has enabled=false in the index)
        mockSearch(createSearchResponse(createHit(RULE_1), createHit(RULE_3)));

        WIndexDetectorRequest request = this.service.buildDetectorRequest(doc, true);

        // Verify the query was built with ALL three candidate IDs
        verify(this.client).prepareSearch(Constants.INDEX_RULES);
        assertQueryCorrect(RULE_1, RULE_2, RULE_3);

        // Verify only the enabled rules are in the detector
        assertNotNull("Detector should be created when some rules are enabled", request);
        List<String> rules = request.getRules();
        assertEquals(2, rules.size());
        assertTrue(rules.contains(RULE_1));
        assertTrue(rules.contains(RULE_3));
        assertFalse("Disabled rule should not be in detector", rules.contains(RULE_2));
    }

    /** All rules disabled: query sent with all candidates, returns null (empty result). */
    public void testAllRulesDisabledReturnsNull() throws Exception {
        JsonNode doc = integrationDoc(RULE_1, RULE_2);
        mockSearch(createEmptySearchResponse());

        WIndexDetectorRequest request = this.service.buildDetectorRequest(doc, true);

        // Verify the query was still built correctly with both IDs
        verify(this.client).prepareSearch(Constants.INDEX_RULES);
        assertQueryCorrect(RULE_1, RULE_2);

        // No enabled rules → no detector
        assertNull("Detector should not be created when all rules are disabled", request);
    }
}
