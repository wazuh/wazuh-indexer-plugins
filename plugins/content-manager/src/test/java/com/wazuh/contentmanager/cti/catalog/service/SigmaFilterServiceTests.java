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
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchResponseSections;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
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

        assertEquals("draft copy", found.get().get(RULE_ID).at("/document/metadata/title").asText());
        assertEquals("draft", found.get().get(RULE_ID).at("/space/name").asText());
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

    public void testFiltersByRuleCanReadTheFiltersOfSomeRulesOnly() {
        stubSearch();

        this.service.filtersByRule(
                Space.CUSTOM, List.of(RULE_ID), ActionListener.wrap(r -> {}, e -> fail()));

        String query = this.lastSearch.get().source().query().toString();
        assertTrue(query, query.contains(Constants.Q_SIGMA_FILTER_RULES) && query.contains(RULE_ID));
    }

    public void testFindRulesInSpaceReadsThatSpaceOnly() {
        stubSearch(rule("custom", "apache-http", "custom copy"));
        AtomicReference<Map<String, JsonNode>> found = new AtomicReference<>();

        this.service.findRulesInSpace(
                List.of(RULE_ID), Space.CUSTOM, ActionListener.wrap(found::set, e -> fail(e.getMessage())));

        assertEquals("custom copy", found.get().get(RULE_ID).at("/metadata/title").asText());
        String query = this.lastSearch.get().source().query().toString();
        assertTrue(query, query.contains("custom") && !query.contains("standard"));
    }

    // ── Validation of the composed rule by Security Analytics ───────────────

    /**
     * A service whose Security Analytics answers validateRule of a composed rule with the given
     * outcome, and accepts the rule alone.
     */
    private SigmaFilterService validatingService(Exception failure, List<JsonNode> validated) {
        return validatingService(failure, validated, false);
    }

    /**
     * A service whose Security Analytics answers validateRule of a composed rule with the given
     * outcome, and of the rule alone with the same outcome if {@code ruleAloneInvalid}.
     */
    private SigmaFilterService validatingService(
            Exception failure, List<JsonNode> validated, boolean ruleAloneInvalid) {
        SecurityAnalyticsService sap = mock(SecurityAnalyticsService.class);
        doAnswer(
                        invocation -> {
                            JsonNode rule = invocation.getArgument(0);
                            validated.add(rule);
                            ActionListener<ActionResponse> l = invocation.getArgument(2);
                            boolean composed = rule.at("/detection/condition").asText().contains("_filt_");
                            if (failure == null || (!composed && !ruleAloneInvalid)) {
                                l.onResponse(null);
                            } else {
                                l.onFailure(failure);
                            }
                            return null;
                        })
                .when(sap)
                .validateRule(any(), any(), any());
        return new SigmaFilterService(this.client, sap);
    }

    public void testCheckTargetsHasSecurityAnalyticsValidateTheComposedRule() throws Exception {
        stubSearch(rule("standard", "apache-http", "standard"));
        List<JsonNode> validated = new java.util.ArrayList<>();
        AtomicReference<String> error = new AtomicReference<>("not called");

        validatingService(null, validated)
                .checkTargets(
                        filter("apache-http"),
                        Space.DRAFT,
                        ActionListener.wrap(error::set, e -> fail(e.getMessage())));

        assertNull(error.get());
        assertEquals(1, validated.size());
        assertEquals(
                "(selection) and (not _filt_a177600000_selection)",
                validated.get(0).at("/detection/condition").asText());
    }

    public void testCheckTargetsReportsASecurityAnalyticsRejection() throws Exception {
        stubSearch(rule("standard", "apache-http", "standard"));
        AtomicReference<String> error = new AtomicReference<>();

        validatingService(
                        new OpenSearchStatusException(
                                "{\"SigmaError\":\"The following fields are not part of the Wazuh Common Schema"
                                        + " (WCS): [user.nam]\"}",
                                RestStatus.BAD_REQUEST),
                        new java.util.ArrayList<>())
                .checkTargets(
                        filter("apache-http"),
                        Space.DRAFT,
                        ActionListener.wrap(error::set, e -> fail(e.getMessage())));

        assertEquals(
                "With the filter applied, rule ["
                        + RULE_ID
                        + "] is not valid: The following fields are not part of the Wazuh Common Schema"
                        + " (WCS): [user.nam]",
                error.get());
    }

    public void testCheckTargetsBlamesTheRuleWhenItIsInvalidWithoutTheFilter() throws Exception {
        stubSearch(rule("standard", "apache-http", "standard"));
        List<JsonNode> validated = new java.util.ArrayList<>();
        AtomicReference<String> error = new AtomicReference<>();

        validatingService(
                        new OpenSearchStatusException(
                                "{\"error\":\"The rule compiles to a query that does not parse: NOT NOT a\"}",
                                RestStatus.BAD_REQUEST),
                        validated,
                        true)
                .checkTargets(
                        filter("apache-http"),
                        Space.DRAFT,
                        ActionListener.wrap(error::set, e -> fail(e.getMessage())));

        assertEquals(2, validated.size());
        assertEquals("selection", validated.get(1).at("/detection/condition").asText());
        assertTrue(
                error.get(),
                error
                        .get()
                        .startsWith(
                                "Rule ["
                                        + RULE_ID
                                        + "] is not valid even without the filter, so no filter can be applied to"
                                        + " it: "));
    }

    public void testCheckTargetsFailsWhenSecurityAnalyticsCannotAnswer() throws Exception {
        stubSearch(rule("standard", "apache-http", "standard"));
        AtomicReference<Exception> failure = new AtomicReference<>();

        validatingService(
                        new OpenSearchStatusException("unavailable", RestStatus.SERVICE_UNAVAILABLE),
                        new java.util.ArrayList<>())
                .checkTargets(
                        filter("apache-http"),
                        Space.DRAFT,
                        ActionListener.wrap(r -> fail("expected a failure, got " + r), failure::set));

        assertNotNull(failure.get());
    }

    public void testLogtestFilterSpace() {
        assertEquals(Space.CUSTOM, SigmaFilterService.resolveLogtestFilterSpace(null, Space.STANDARD));
        assertEquals(Space.CUSTOM, SigmaFilterService.resolveLogtestFilterSpace(null, Space.CUSTOM));
        assertEquals(Space.TEST, SigmaFilterService.resolveLogtestFilterSpace(null, Space.TEST));
        assertEquals(Space.TEST, SigmaFilterService.resolveLogtestFilterSpace("test", Space.STANDARD));
        assertEquals(Space.CUSTOM, SigmaFilterService.resolveLogtestFilterSpace("CUSTOM", Space.TEST));
        assertNull(SigmaFilterService.resolveLogtestFilterSpace("none", Space.STANDARD));
        IllegalArgumentException e =
                expectThrows(
                        IllegalArgumentException.class,
                        () -> SigmaFilterService.resolveLogtestFilterSpace("draft", Space.STANDARD));
        assertEquals(
                "Invalid 'sigma_filters' value [draft]. Must be one of: test, custom, none.",
                e.getMessage());
    }

    public void testCheckTargetsPassesOnAPermissionFailure() throws Exception {
        stubSearch(rule("standard", "apache-http", "standard"));
        AtomicReference<Exception> failure = new AtomicReference<>();
        Exception forbidden =
                new org.opensearch.OpenSearchSecurityException(
                        "no permissions for [cluster:admin/wazuh/securityanalytics/rule/validate]",
                        RestStatus.FORBIDDEN);

        validatingService(forbidden, new java.util.ArrayList<>())
                .checkTargets(
                        filter("apache-http"),
                        Space.DRAFT,
                        ActionListener.wrap(r -> fail("expected a failure, got " + r), failure::set));

        assertSame(forbidden, failure.get());
    }
}
