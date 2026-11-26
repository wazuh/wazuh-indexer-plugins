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
package com.wazuh.contentmanager.cti.catalog.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.utils.SigmaFilterComposer.ComposeException;

/** Tests for {@link SigmaFilterComposer}. */
public class SigmaFilterComposerTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String RULE_ID = "26a8d32e-0838-5589-948c-501b5a301cf5";
    private static final String F1 = "a1776000-0000-4000-8000-000000000001";
    private static final String F2 = "b2776000-0000-4000-8000-000000000002";
    private static final String P1 = "_filt_a177600000_";
    private static final String P2 = "_filt_b277600000_";
    private static final String LS = "{'product':'apache-http'}";
    private static final String GIT =
            "{'selection':{'url.original|contains':['.git/']},'condition':'selection'}";

    private static JsonNode json(String s) throws Exception {
        return MAPPER.readTree(s.replace('\'', '"'));
    }

    private static JsonNode rule(String detection) throws Exception {
        return json(
                "{'id':'"
                        + RULE_ID
                        + "','metadata':{'title':'r'},"
                        + "'logsource':{'category':'webserver','product':'apache-http'},"
                        + "'detection':"
                        + detection
                        + "}");
    }

    private static JsonNode filter(String id, String logsource, String body) throws Exception {
        return json(
                "{'id':'"
                        + id
                        + "','enabled':true,'logsource':"
                        + logsource
                        + ",'filter':{'rules':['"
                        + RULE_ID
                        + "'],"
                        + body
                        + "}}");
    }

    private static String condition(JsonNode rule) {
        return rule.at("/detection/condition").asText();
    }

    public void testPrefixTakesTheFirstTenHexDigitsOfTheId() {
        assertEquals(P1, SigmaFilterComposer.prefix(F1));
        assertEquals(
                "_filt_0123456789_", SigmaFilterComposer.prefix("01234567-89AB-4CDE-8F01-23456789ABCD"));
    }

    public void testOneFilterIsAppendedAndPrefixed() throws Exception {
        JsonNode rule = rule(GIT);
        JsonNode f =
                filter(
                        F1,
                        LS,
                        "'selection':{'user_agent.original|startswith':'internal-scanner'},"
                                + "'condition':'not selection'");

        JsonNode out = SigmaFilterComposer.compose(rule, List.of(f));

        assertEquals("(selection) and (not " + P1 + "selection)", condition(out));
        assertEquals(
                "internal-scanner",
                out.at("/detection/" + P1 + "selection/user_agent.original|startswith").asText());
        // The rule is never modified.
        assertEquals("selection", condition(rule));
        assertFalse(rule.at("/detection").has(P1 + "selection"));
    }

    public void testFiltersAreAppliedInTheOrderOfTheirIds() throws Exception {
        JsonNode rule = rule(GIT);
        JsonNode f2 =
                filter(
                        F2,
                        LS,
                        "'selection_dc':{'host.name':['DC-01']},'selection_svc':{'user.name|endswith':'$'},"
                                + "'condition':'not 1 of selection*'");
        JsonNode f1 = filter(F1, LS, "'selection':{'user.name':'x'},'condition':'not selection'");

        String c1 = condition(SigmaFilterComposer.compose(rule, List.of(f2, f1)));
        String c2 = condition(SigmaFilterComposer.compose(rule, List.of(f1, f2)));

        assertEquals(c1, c2);
        assertEquals(
                "(selection) and (not " + P1 + "selection) and (not 1 of " + P2 + "selection*)", c1);
    }

    public void testThemAndGroupsInTheFilterConditionArePrefixed() throws Exception {
        JsonNode rule = rule(GIT);
        JsonNode them =
                filter(F1, LS, "'a':{'user.name':'x'},'b':{'host.name':'y'},'condition':'not all of them'");
        JsonNode group =
                filter(F2, LS, "'a':{'user.name':'x'},'b':{'host.name':'y'},'condition':'not (a or b)'");

        assertEquals(
                "(selection) and (not all of " + P1 + "*)",
                condition(SigmaFilterComposer.compose(rule, List.of(them))));
        assertEquals(
                "(selection) and (not (" + P2 + "a or " + P2 + "b))",
                condition(SigmaFilterComposer.compose(rule, List.of(group))));
    }

    public void testTheRuleSelectorsAreKeptAsTheyAre() throws Exception {
        // Security Analytics skips the composed identifiers in `them`: nothing is expanded.
        JsonNode rule =
                rule(
                        "{'sel_a':{'process.name':'nc'},'sel_b':{'process.args':'-e'},"
                                + "'condition':'all of them'}");
        JsonNode f = filter(F1, LS, "'selection':{'user.name':'x'},'condition':'not selection'");

        assertEquals(
                "(all of them) and (not " + P1 + "selection)",
                condition(SigmaFilterComposer.compose(rule, List.of(f))));
    }

    public void testNoFiltersReturnTheRule() throws Exception {
        JsonNode rule = rule(GIT);

        assertSame(rule, SigmaFilterComposer.compose(rule, List.of()));
    }

    public void testFilterRejections() throws Exception {
        JsonNode rule = rule(GIT);
        String[][] bad = {
            // The other convention: applying it would silently invert the filter.
            {LS, "'selection':{'user.name':'a'},'condition':'selection'"},
            // `not` binds tighter than `and`: only `a` would be negated.
            {LS, "'a':{'user.name':'a'},'b':{'host.name':'b'},'condition':'not a and b'"},
            // Only one top-level negation in this version.
            {LS, "'a':{'user.name':'a'},'b':{'host.name':'b'},'condition':'not (a and not b)'"},
            // A logsource key the filter sets differs from the rule's.
            {"{'product':'windows'}", "'selection':{'user.name':'a'},'condition':'not selection'"},
            // The condition refers to a selection the filter does not define.
            {LS, "'selection':{'user.name':'a'},'condition':'not other'"},
            {LS, "'selection':{'user.name':'a'},'condition':'not 1 of other*'"},
            // Not a valid condition, or not a valid identifier for Security Analytics.
            {LS, "'selection':{'user.name':'a'},'condition':'not selection |'"},
            {LS, "'sel-1':{'user.name':'a'},'condition':'not sel-1'"},
            {LS, "'selection':{'user.name':'a'},'condition':'NOT selection'"},
            // No selection.
            {LS, "'condition':'not selection'"},
        };
        for (String[] b : bad) {
            JsonNode f = filter(F1, b[0], b[1]);
            expectThrows(
                    ComposeException.class,
                    "filter " + b[1],
                    () -> SigmaFilterComposer.compose(rule, List.of(f)));
        }
        for (String rules : List.of("'any'", "[]", "[1]")) {
            JsonNode f =
                    json(
                            "{'id':'"
                                    + F1
                                    + "','logsource':"
                                    + LS
                                    + ",'filter':{'rules':"
                                    + rules
                                    + ",'selection':{'user.name':'a'},'condition':'not selection'}}");
            expectThrows(ComposeException.class, () -> SigmaFilterComposer.compose(rule, List.of(f)));
        }
        JsonNode noLogsource =
                json(
                        "{'id':'"
                                + F1
                                + "','filter':{'rules':['"
                                + RULE_ID
                                + "'],'selection':{'user.name':'a'},'condition':'not selection'}}");
        expectThrows(ComposeException.class, () -> SigmaFilterComposer.validateFilter(noLogsource));
    }

    public void testRuleRejections() throws Exception {
        JsonNode f = filter(F1, LS, "'selection':{'user.name':'x'},'condition':'not selection'");
        String[] bad = {
            // Aggregations.
            "{'selection':{'user.name':'a'},'condition':'selection | count() by host.name > 5'}",
            "{'selection':{'user.name':'a'},'timeframe':'5m','condition':'selection'}",
            // A condition list.
            "{'selection':{'user.name':'a'},'condition':['selection']}",
            // The composed identifier exists in the rule already.
            "{'selection':{'user.name':'a'},'"
                    + P1
                    + "selection':{'host.name':'b'},'condition':'selection'}",
            // A rule selector starting with '_' would select the composed identifiers.
            "{'selection':{'user.name':'a'},'_x':{'host.name':'b'},'condition':'selection and not 1 of _*'}",
        };
        for (String detection : bad) {
            JsonNode rule = rule(detection);
            expectThrows(
                    ComposeException.class,
                    "rule " + detection,
                    () -> SigmaFilterComposer.compose(rule, List.of(f)));
        }
    }

    public void testValidateFilterReturnsTheSelections() throws Exception {
        JsonNode f =
                filter(
                        F1,
                        LS,
                        "'sel_a':{'user.name':'x'},'sel_b':{'host.name':'y'},'condition':'not 1 of sel_*'");

        assertEquals(List.of("sel_a", "sel_b"), SigmaFilterComposer.validateFilter(f));
    }

    public void testLogsourceIsMatchedOnTheKeysTheFilterSets() throws Exception {
        JsonNode ruleLogsource = json("{'category':'process_creation','product':'windows'}");

        assertTrue(
                SigmaFilterComposer.logsourceContained(json("{'product':'windows'}"), ruleLogsource));
        assertTrue(SigmaFilterComposer.logsourceContained(json("{}"), ruleLogsource));
        assertFalse(SigmaFilterComposer.logsourceContained(json("{'product':'linux'}"), ruleLogsource));
        assertFalse(
                SigmaFilterComposer.logsourceContained(json("{'service':'sysmon'}"), ruleLogsource));
    }

    public void testApplyOrKeepReturnsTheRuleWhenNoFilterFits() throws Exception {
        JsonNode rule = rule(GIT);
        JsonNode mismatch =
                filter(
                        F1,
                        "{'product':'windows'}",
                        "'selection':{'user.name':'a'},'condition':'not selection'");

        assertSame(rule, SigmaFilterComposer.applyOrKeep(rule, Map.of(RULE_ID, List.of(mismatch))));
        assertSame(rule, SigmaFilterComposer.applyOrKeep(rule, Map.of()));
    }

    public void testApplyOrKeepSkipsOnlyTheFilterThatNoLongerFits() throws Exception {
        JsonNode rule = rule(GIT);
        JsonNode fits =
                filter(
                        F1,
                        LS,
                        "'selection':{'user_agent.original|startswith':'scanner'},'condition':'not selection'");
        JsonNode mismatch =
                filter(
                        F2,
                        "{'product':'windows'}",
                        "'selection':{'user.name':'a'},'condition':'not selection'");

        JsonNode out = SigmaFilterComposer.applyOrKeep(rule, Map.of(RULE_ID, List.of(mismatch, fits)));

        assertEquals("(selection) and (not " + P1 + "selection)", condition(out));
        assertFalse(out.at("/detection").has(P2 + "selection"));
    }

    public void testApplyOrKeepSkipsDisabledFilters() throws Exception {
        JsonNode rule = rule(GIT);
        JsonNode disabled =
                json(
                        "{'id':'"
                                + F1
                                + "','enabled':false,'logsource':"
                                + LS
                                + ",'filter':{'rules':['"
                                + RULE_ID
                                + "'],'selection':{'user.name':'a'},'condition':'not selection'}}");

        assertSame(rule, SigmaFilterComposer.applyOrKeep(rule, Map.of(RULE_ID, List.of(disabled))));
    }
}
