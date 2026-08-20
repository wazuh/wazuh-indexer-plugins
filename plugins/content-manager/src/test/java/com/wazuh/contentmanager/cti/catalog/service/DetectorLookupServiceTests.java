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
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.cti.catalog.model.Space;

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
        SearchHit[] hits = new SearchHit[sources.length];
        for (int i = 0; i < sources.length; i++) {
            SearchHit hit = new SearchHit(i, String.valueOf(i), null, null);
            hit.sourceRef(new BytesArray(sources[i]));
            hits[i] = hit;
        }
        SearchHits searchHits =
                new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f);
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
     * The nested query runs against a {@code text} field, so it can return detectors that merely
     * share a UUID token. Those must be discarded by the intersection check.
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

    /** An empty id set short-circuits without querying. */
    public void testFindDetectorsUsingRulesWithNoIds() {
        AtomicReference<List<DetectorLookupService.DetectorRules>> result = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of(), ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertTrue(result.get().isEmpty());
    }

    /** A missing detectors index yields an empty list rather than an error. */
    @SuppressWarnings("unchecked")
    public void testFindDetectorsUsingRulesToleratesMissingIndex() {
        doAnswer(
                        invocation -> {
                            ActionListener<SearchResponse> listener =
                                    (ActionListener<SearchResponse>) invocation.getArguments()[1];
                            listener.onFailure(new RuntimeException("index_not_found_exception"));
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any(ActionListener.class));

        AtomicReference<List<DetectorLookupService.DetectorRules>> result = new AtomicReference<>();
        this.service.findDetectorsUsingRules(
                Set.of("r1"), ActionListener.wrap(result::set, e -> fail(e.getMessage())));

        assertTrue(result.get().isEmpty());
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
