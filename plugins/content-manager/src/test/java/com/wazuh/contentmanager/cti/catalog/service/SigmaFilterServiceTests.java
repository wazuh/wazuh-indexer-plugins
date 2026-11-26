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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/** Unit tests for {@link SigmaFilterService}. */
public class SigmaFilterServiceTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String RULE_ID = "26a8d32e-0838-5589-948c-501b5a301cf5";
    private static final String FILTER_ID = "a1776000-0000-4000-8000-000000000001";

    private Client client;
    private SigmaFilterService service;
    private final AtomicReference<SearchRequest> lastSearch = new AtomicReference<>();

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        this.service = new SigmaFilterService(this.client);
    }

    private static String rule(String space, String product, String title) {
        return ("{'space':{'name':'"
                        + space
                        + "'},'document':{'id':'"
                        + RULE_ID
                        + "','metadata':{'title':'"
                        + title
                        + "'},'logsource':{'product':'"
                        + product
                        + "'},'detection':{'selection':{'url.original|contains':'.git/'},"
                        + "'condition':'selection'}}}")
                .replace('\'', '"');
    }

    private static JsonNode filter(String product) throws Exception {
        return MAPPER.readTree(
                ("{'id':'"
                                + FILTER_ID
                                + "','logsource':{'product':'"
                                + product
                                + "'},'filter':{'rules':['"
                                + RULE_ID
                                + "'],'selection':{'user.name':'adm'},'condition':'not selection'}}")
                        .replace('\'', '"'));
    }

    /** Stubs client.search to answer with hits carrying the given sources. */
    @SuppressWarnings("unchecked")
    private void stubSearch(String... sources) {
        SearchHit[] hits = new SearchHit[sources.length];
        for (int i = 0; i < sources.length; i++) {
            hits[i] = new SearchHit(i, String.valueOf(i), null, null);
            hits[i].sourceRef(new BytesArray(sources[i]));
        }
        SearchHits searchHits =
                new SearchHits(hits, new TotalHits(hits.length, TotalHits.Relation.EQUAL_TO), 1.0f);
        SearchResponse response =
                new SearchResponse(
                        new SearchResponseSections(searchHits, null, null, false, null, null, 1),
                        null,
                        1,
                        1,
                        0,
                        100,
                        null,
                        null);
        doAnswer(
                        invocation -> {
                            this.lastSearch.set(invocation.getArgument(0));
                            ((ActionListener<SearchResponse>) invocation.getArgument(1)).onResponse(response);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any(ActionListener.class));
    }

    public void testFindRulesPrefersTheFilterSpaceCopy() {
        stubSearch(
                rule("draft", "apache-http", "draft copy"), rule("standard", "apache-http", "standard"));
        AtomicReference<Map<String, JsonNode>> found = new AtomicReference<>();

        this.service.findRules(
                List.of(RULE_ID), Space.DRAFT, ActionListener.wrap(found::set, e -> fail(e.getMessage())));

        assertEquals("draft copy", found.get().get(RULE_ID).at("/metadata/title").asText());
        assertEquals(Constants.INDEX_RULES, this.lastSearch.get().indices()[0]);
        String query = this.lastSearch.get().source().query().toString();
        assertTrue(query, query.contains("standard") && query.contains("draft"));
    }

    public void testCheckTargetsAcceptsAFilterThatFitsItsRule() throws Exception {
        stubSearch(rule("standard", "apache-http", "standard"));
        AtomicReference<String> error = new AtomicReference<>("not called");

        this.service.checkTargets(
                filter("apache-http"),
                Space.DRAFT,
                ActionListener.wrap(error::set, e -> fail(e.getMessage())));

        assertNull(error.get());
    }

    public void testCheckTargetsRejectsAnUnknownRule() throws Exception {
        stubSearch();
        AtomicReference<String> error = new AtomicReference<>();

        this.service.checkTargets(
                filter("apache-http"),
                Space.DRAFT,
                ActionListener.wrap(error::set, e -> fail(e.getMessage())));

        assertEquals(
                "Rule [" + RULE_ID + "] not found in the standard or the draft space.", error.get());
    }

    public void testCheckTargetsRejectsALogsourceMismatch() throws Exception {
        stubSearch(rule("standard", "apache-http", "standard"));
        AtomicReference<String> error = new AtomicReference<>();

        this.service.checkTargets(
                filter("windows"), Space.DRAFT, ActionListener.wrap(error::set, e -> fail(e.getMessage())));

        assertNotNull(error.get());
        assertTrue(error.get(), error.get().contains("does not match the logsource"));
    }

    public void testFiltersByRuleGroupsTheFiltersOfASpaceByTargetRule() {
        stubSearch(
                "{'space':{'name':'custom'},'document':{'id':'f1','filter':{'rules':['r1','r2']}}}"
                        .replace('\'', '"'),
                "{'space':{'name':'custom'},'document':{'id':'f2','filter':{'rules':['r1']}}}"
                        .replace('\'', '"'));
        AtomicReference<Map<String, List<JsonNode>>> byRule = new AtomicReference<>();

        this.service.filtersByRule(
                Space.CUSTOM, ActionListener.wrap(byRule::set, e -> fail(e.getMessage())));

        assertEquals(2, byRule.get().get("r1").size());
        assertEquals("f1", byRule.get().get("r2").get(0).path("id").asText());
        assertEquals(Constants.INDEX_SIGMA_FILTERS, this.lastSearch.get().indices()[0]);
        assertTrue(this.lastSearch.get().source().query().toString().contains("custom"));
    }

    @SuppressWarnings("unchecked")
    public void testFiltersByRuleYieldsNoFiltersWhenTheReadFails() {
        doAnswer(
                        invocation -> {
                            ((ActionListener<SearchResponse>) invocation.getArgument(1))
                                    .onFailure(new RuntimeException("shards failed"));
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any(ActionListener.class));
        AtomicReference<Map<String, List<JsonNode>>> byRule = new AtomicReference<>();

        this.service.filtersByRule(
                Space.CUSTOM, ActionListener.wrap(byRule::set, e -> fail(e.getMessage())));

        assertTrue(byRule.get().isEmpty());
    }
}
