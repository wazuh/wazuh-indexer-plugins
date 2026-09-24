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
package com.wazuh.contentmanager.cti.catalog.service;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchResponseSections;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/** Unit tests for {@link DetectorLookupService}. */
public class DetectorLookupServiceTests extends OpenSearchTestCase {

    private Client client;
    private DetectorLookupService service;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        this.service = new DetectorLookupService(this.client);
    }

    /** Builds a SearchResponse whose hits carry the given raw JSON sources. */
    private SearchResponse searchResponseOf(String... sources) {
        return searchResponseWithTotal(sources.length, sources);
    }

    /** Builds a SearchResponse reporting {@code total} hits but carrying only the given sources. */
    private SearchResponse searchResponseWithTotal(long total, String... sources) {
        SearchHit[] hits = new SearchHit[sources.length];
        for (int i = 0; i < sources.length; i++) {
            SearchHit hit = new SearchHit(i, String.valueOf(i), null, null);
            hit.sourceRef(new BytesArray(sources[i]));
            hits[i] = hit;
        }
        SearchHits searchHits =
                new SearchHits(hits, new TotalHits(total, TotalHits.Relation.EQUAL_TO), 1.0f);
        SearchResponseSections sections =
                new SearchResponseSections(searchHits, null, null, false, null, null, 1);
        return new SearchResponse(sections, null, 1, 1, 0, 100, null, null);
    }

    /** Stubs client.search to answer with the given response. */
    @SuppressWarnings("unchecked")
    private void stubSearch(SearchResponse response) {
        doAnswer(
                        invocation -> {
                            ActionListener<SearchResponse> listener =
                                    (ActionListener<SearchResponse>) invocation.getArguments()[1];
                            listener.onResponse(response);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any(ActionListener.class));
    }

    /** Enabled detectors referencing one of the requested rules are returned with their rule ids. */
    public void testFindDetectorsUsingRulesReturnsRuleIds() {
        stubSearch(
                searchResponseOf(
                        "{\"detector\":{\"name\":\"d1\",\"enabled\":true,\"inputs\":[{\"detector_input\":"
                                + "{\"custom_rules\":[{\"id\":\"r1\"},{\"id\":\"r2\"}]}}]}}"));

        AtomicReference<List<DetectorLookupService.DetectorRules>> result = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of("r1"), ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertEquals(1, result.get().size());
        assertEquals("d1", result.get().get(0).name());
        assertEquals(List.of("r1", "r2"), result.get().get(0).ruleIds());
    }

    /** Disabled detectors are filtered out: a stopped detector needs no protection. */
    public void testFindDetectorsUsingRulesSkipsDisabledOnes() {
        stubSearch(
                searchResponseOf(
                        "{\"detector\":{\"name\":\"off\",\"enabled\":false,\"inputs\":[{\"detector_input\":"
                                + "{\"custom_rules\":[{\"id\":\"r1\"}]}}]}}"));

        AtomicReference<List<DetectorLookupService.DetectorRules>> result = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of("r1"), ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertTrue(result.get().isEmpty());
    }

    /**
     * The search reads every enabled detector, so detectors that reference none of the promoted rules
     * come back too. Those must be discarded by the intersection check.
     */
    public void testFindDetectorsUsingRulesDiscardsOverMatches() {
        stubSearch(
                searchResponseOf(
                        "{\"detector\":{\"name\":\"unrelated\",\"enabled\":true,\"inputs\":[{\"detector_input\":"
                                + "{\"custom_rules\":[{\"id\":\"other\"}]}}]}}"));

        AtomicReference<List<DetectorLookupService.DetectorRules>> result = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of("r1"), ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertTrue(result.get().isEmpty());
    }

    /**
     * The query must not grow with the number of promoted rules. One clause per rule id used to
     * exceed {@code indices.query.bool.max_clause_count} past about 200 rules and fail the promotion
     * on every shard (wazuh-indexer#1945).
     */
    @SuppressWarnings("unchecked")
    public void testFindDetectorsUsingRulesQueryDoesNotDependOnRuleIds() {
        AtomicReference<SearchRequest> captured = new AtomicReference<>();
        doAnswer(
                        invocation -> {
                            captured.set(invocation.getArgument(0));
                            ((ActionListener<SearchResponse>) invocation.getArguments()[1])
                                    .onResponse(searchResponseOf());
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any(ActionListener.class));

        Set<String> ruleIds = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            ruleIds.add(UUID.randomUUID().toString());
        }
        this.service.findDetectorsUsingRules(
                ruleIds, ActionListener.wrap(r -> {}, e -> fail(e.getMessage())));

        // Security Analytics maps "detector" as nested: a bare term query on detector.enabled would
        // match no detector at all and let every promotion through unchecked.
        QueryBuilder query = captured.get().source().query();
        assertTrue(query instanceof NestedQueryBuilder);
        QueryBuilder inner = ((NestedQueryBuilder) query).query();
        assertTrue(inner instanceof TermQueryBuilder);
        assertEquals("detector.enabled", ((TermQueryBuilder) inner).fieldName());
        assertEquals(true, ((TermQueryBuilder) inner).value());
        assertFalse(
                "the query must not carry the rule ids",
                query.toString().contains(ruleIds.iterator().next()));
    }

    /**
     * More enabled detectors than one search returns fails the lookup: the ones left out would
     * otherwise go unchecked and the promotion could empty them.
     */
    public void testFindDetectorsUsingRulesFailsWhenResultIsTruncated() {
        stubSearch(
                searchResponseWithTotal(
                        Constants.MAX_RESULT_WINDOW + 1,
                        "{\"detector\":{\"name\":\"d1\",\"enabled\":true,\"inputs\":[{\"detector_input\":"
                                + "{\"custom_rules\":[{\"id\":\"r1\"}]}}]}}"));

        AtomicReference<Exception> failure = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of("r1"),
                ActionListener.wrap(r -> fail("a truncated result must not be trusted"), failure::set));

        assertTrue(failure.get() instanceof IllegalStateException);
    }

    /** An empty id set short-circuits without querying. */
    public void testFindDetectorsUsingRulesWithNoIds() {
        AtomicReference<List<DetectorLookupService.DetectorRules>> result = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of(), ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertTrue(result.get().isEmpty());
    }

    /**
     * A cluster with no detectors yet answers with no hits, not with an error: the search is issued
     * with {@code LENIENT_EXPAND_OPEN}, which resolves a missing index to an empty result.
     */
    public void testFindDetectorsUsingRulesToleratesMissingIndex() {
        stubSearch(searchResponseOf());

        AtomicReference<List<DetectorLookupService.DetectorRules>> result = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of("r1"), ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertTrue(result.get().isEmpty());
    }

    /**
     * Any other search failure is propagated. Returning an empty list would read as "no detector
     * references these rules" and let a promotion through on a guard that never ran.
     */
    @SuppressWarnings("unchecked")
    public void testFindDetectorsUsingRulesPropagatesSearchFailures() {
        doAnswer(
                        invocation -> {
                            ActionListener<SearchResponse> listener =
                                    (ActionListener<SearchResponse>) invocation.getArguments()[1];
                            listener.onFailure(new RuntimeException("shard failure"));
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any(ActionListener.class));

        AtomicReference<Exception> failure = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of("r1"),
                ActionListener.wrap(r -> fail("the failure should not be swallowed"), failure::set));

        assertNotNull(failure.get());
        assertEquals("shard failure", failure.get().getMessage());
    }

    /** Rule states are keyed by document id, defaulting to enabled when the field is absent. */
    public void testFetchRuleEnabledStates() {
        stubSearch(
                searchResponseOf(
                        "{\"document\":{\"id\":\"r1\",\"enabled\":false}}", "{\"document\":{\"id\":\"r2\"}}"));

        AtomicReference<Map<String, Boolean>> result = new AtomicReference<>();
        this.service.fetchRuleEnabledStates(
                Set.of("r1", "r2"),
                Space.CUSTOM,
                ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertFalse(result.get().get("r1"));
        assertTrue(result.get().get("r2"));
    }

    /** An empty id set short-circuits without querying. */
    public void testFetchRuleEnabledStatesWithNoIds() {
        AtomicReference<Map<String, Boolean>> result = new AtomicReference<>();
        this.service.fetchRuleEnabledStates(
                Set.of(), Space.CUSTOM, ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertTrue(result.get().isEmpty());
    }
}
