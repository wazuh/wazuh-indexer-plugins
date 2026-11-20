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

import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Assert;
import org.junit.Before;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Unit tests for {@link StandardSpaceReconciler}, the diff that deletes from Security Analytics the
 * standard content CTI no longer publishes (wazuh-indexer-plugins#1818).
 *
 * <p>The diff itself is pure and tested directly. The deletions are tested against a stubbed
 * Security Analytics service, and the guards against a stand-in for the reads.
 */
public class StandardSpaceReconcilerTests extends OpenSearchTestCase {

    private SecurityAnalyticsService sapService;
    private Client client;

    /** Every deletion the stubbed service was asked for, in order. */
    private List<String> calls;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(Settings.EMPTY);
        this.client = mock(Client.class);
        this.sapService = mock(SecurityAnalyticsService.class);
        this.calls = Collections.synchronizedList(new ArrayList<>());
    }

    // --- Helpers ---------------------------------------------------------------------------

    /** Makes every deletion on the stubbed service succeed, recording the order they came in. */
    private void stubDeletionsSucceeding() {
        doAnswer(
                        invocation -> {
                            this.calls.add("detector:" + invocation.getArgument(0));
                            invocation.<ActionListener<?>>getArgument(1).onResponse(null);
                            return null;
                        })
                .when(this.sapService)
                .deleteDetector(anyString(), any());
        doAnswer(
                        invocation -> {
                            this.calls.add("rule:" + invocation.getArgument(0));
                            invocation.<ActionListener<?>>getArgument(2).onResponse(null);
                            return null;
                        })
                .when(this.sapService)
                .deleteRule(anyString(), any(), any());
        doAnswer(
                        invocation -> {
                            this.calls.add("integration:" + invocation.getArgument(0));
                            invocation.<ActionListener<?>>getArgument(2).onResponse(null);
                            return null;
                        })
                .when(this.sapService)
                .deleteIntegration(anyString(), any(), any());
    }

    /** A reconciler whose reads are replaced by a fixed inventory. */
    private StandardSpaceReconciler reconcilerReading(StandardSpaceReconciler.Inventory inventory) {
        return new StandardSpaceReconciler(this.client, this.sapService) {
            @Override
            StandardSpaceReconciler.Inventory read() {
                return inventory;
            }
        };
    }

    /** A reconciler whose reads fail. */
    private StandardSpaceReconciler reconcilerFailingToRead() {
        return new StandardSpaceReconciler(this.client, this.sapService) {
            @Override
            StandardSpaceReconciler.Inventory read() {
                throw new IllegalStateException("the search failed");
            }
        };
    }

    private static StandardSpaceReconciler.Inventory inventory(
            Map<String, List<String>> contentIntegrations,
            Set<String> contentRules,
            Set<String> sapIntegrations,
            Set<String> sapRules,
            Set<String> sapDetectors) {
        return new StandardSpaceReconciler.Inventory(
                contentIntegrations, contentRules, sapIntegrations, sapRules, sapDetectors);
    }

    // --- The diff (scenarios 1, 3, 4 and piece C) --------------------------------------------

    /**
     * Scenario 1: CTI deleted an integration, so Security Analytics is the only side that still has
     * it. Its detector goes with it, which {@code deleteIntegration} does for the standard space.
     */
    public void testPlan_integrationGoneFromContent_isDeleted() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("kept", List.of("rule-1")),
                                Set.of("rule-1"),
                                Set.of("kept", "removed"),
                                Set.of("rule-1"),
                                Set.of("kept")));

        Assert.assertEquals(List.of("removed"), plan.integrations());
        Assert.assertEquals(Collections.emptyList(), plan.rules());
        Assert.assertEquals(Collections.emptyList(), plan.detectors());
    }

    /** Scenario 3: CTI deleted a rule, so it has to go from Security Analytics too. */
    public void testPlan_ruleGoneFromContent_isDeleted() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("integration-1", List.of("rule-1", "rule-2")),
                                Set.of("rule-1"),
                                Set.of("integration-1"),
                                Set.of("rule-1", "rule-2"),
                                Set.of("integration-1")));

        Assert.assertEquals(List.of("rule-2"), plan.rules());
        Assert.assertEquals(Collections.emptyList(), plan.integrations());
        Assert.assertEquals(
                "the integration still has rule-1, so its detector stays",
                Collections.emptyList(),
                plan.detectors());
    }

    /**
     * Piece C. An integration survives but CTI deleted every rule it lists. {@code
     * buildDetectorRequest} returns null for it, so the detectors phase skips it and nothing corrects
     * it: it keeps the monitor it was built with and goes on producing findings from rules that no
     * longer exist. Measured on the issue, so the detector has to be deleted.
     */
    public void testPlan_integrationLeftWithoutRules_losesItsDetector() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("integration-1", List.of("rule-1", "rule-2")),
                                Collections.emptySet(),
                                Set.of("integration-1"),
                                Set.of("rule-1", "rule-2"),
                                Set.of("integration-1")));

        Assert.assertEquals(List.of("integration-1"), plan.detectors());
        Assert.assertEquals(List.of("rule-1", "rule-2"), plan.rules());
        Assert.assertEquals(
                "the integration itself is still published", Collections.emptyList(), plan.integrations());
    }

    /**
     * An integration CTI emptied by unlinking its rules before deleting them is the same case: it
     * lists nothing, so there is nothing left for its detector to match.
     */
    public void testPlan_integrationListingNoRules_losesItsDetector() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("integration-1", Collections.emptyList()),
                                Set.of("rule-of-another"),
                                Set.of("integration-1"),
                                Collections.emptySet(),
                                Set.of("integration-1")));

        Assert.assertEquals(List.of("integration-1"), plan.detectors());
    }

    /**
     * The acotación that makes piece C safe. A user who disables the last rule of an integration also
     * leaves {@code buildDetectorRequest} with nothing to build, so "the detector would not be built"
     * cannot be the trigger. A disabled rule is still a document in the content index, so it keeps
     * the detector out of the plan; only a rule CTI actually deleted takes it there.
     */
    public void testPlan_integrationWhoseRulesTheUserDisabled_keepsItsDetector() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("integration-1", List.of("rule-1")),
                                // rule-1 is present, whatever its enabled flag says.
                                Set.of("rule-1"),
                                Set.of("integration-1"),
                                Set.of("rule-1"),
                                Set.of("integration-1")));

        Assert.assertTrue(
                "a disabled rule must not cost the user their detector", plan.detectors().isEmpty());
        Assert.assertTrue(plan.rules().isEmpty());
        Assert.assertTrue(plan.integrations().isEmpty());
    }

    /**
     * A detector whose integration is gone is deleted by {@code deleteIntegration}, not on its own:
     * asking twice would make the second attempt fail and, because {@code deleteIntegration} chains
     * the log type behind the detector, take the integration deletion with it.
     */
    public void testPlan_detectorOfADeletedIntegration_isNotDeletedTwice() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Collections.emptyMap(),
                                Set.of("rule-1"),
                                Set.of("removed"),
                                Collections.emptySet(),
                                Set.of("removed")));

        Assert.assertEquals(Collections.emptyList(), plan.detectors());
        Assert.assertEquals(List.of("removed"), plan.integrations());
    }

    /** Scenario 4: a change of consumer, where every previous resource is left over at once. */
    public void testPlan_consumerChange_everyPreviousResourceIsStale() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("new-1", List.of("new-rule-1")),
                                Set.of("new-rule-1"),
                                Set.of("new-1", "old-1", "old-2"),
                                Set.of("new-rule-1", "old-rule-1"),
                                Set.of("new-1", "old-1")));

        Assert.assertEquals(List.of("old-1", "old-2"), plan.integrations());
        Assert.assertEquals(List.of("old-rule-1"), plan.rules());
        Assert.assertEquals(Collections.emptyList(), plan.detectors());
    }

    /** The steady state: both sides agree and nothing is deleted. */
    public void testPlan_bothSidesAgree_isEmpty() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("integration-1", List.of("rule-1")),
                                Set.of("rule-1"),
                                Set.of("integration-1"),
                                Set.of("rule-1"),
                                Set.of("integration-1")));

        Assert.assertTrue(plan.isEmpty());
    }

    /**
     * Content Security Analytics has not received yet is not the diff's business: it only deletes.
     */
    public void testPlan_contentNotYetPushed_isNotADeletion() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("integration-1", List.of("rule-1"), "integration-2", List.of("rule-2")),
                                Set.of("rule-1", "rule-2"),
                                Set.of("integration-1"),
                                Set.of("rule-1"),
                                Set.of("integration-1")));

        Assert.assertTrue(plan.isEmpty());
    }

    /**
     * A detector nothing owns on either side has to be deleted here, because nothing else can.
     *
     * <p>Its integration is in neither the content nor Security Analytics, so {@code
     * deleteIntegration} is never called for it. The state is reachable: {@code
     * TransportDeleteDetectorAction} answers any failed read of a detector with {@code NOT_FOUND}, so
     * a transient failure looks like "there was no detector" and the log type is deleted while the
     * detector and its monitor keep running.
     */
    public void testPlan_detectorOwnedByNobody_isDeleted() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("kept", List.of("rule-1")),
                                Set.of("rule-1"),
                                Set.of("kept"),
                                Set.of("rule-1"),
                                Set.of("kept", "orphan")));

        Assert.assertEquals(List.of("orphan"), plan.detectors());
        Assert.assertTrue(plan.integrations().isEmpty());
        Assert.assertTrue(plan.rules().isEmpty());
    }

    /**
     * The two kinds of detector are counted apart, because the log names them apart.
     *
     * <p>Measured on a real deployment: a detector nothing owned carried two live rules, and a single
     * counter reported it as "left without rules", sending whoever read the line to look for an
     * integration that had lost its rules and did not exist.
     */
    public void testPlan_tellsTheTwoKindsOfDetectorApart() {
        StandardSpaceReconciler.Plan plan =
                StandardSpaceReconciler.plan(
                        inventory(
                                // "dry" is still published but every rule it lists is gone; "orphan" is
                                // owned by nobody, and the rule it carries is alive.
                                Map.of("dry", List.of("gone-rule"), "kept", List.of("rule-1")),
                                Set.of("rule-1"),
                                Set.of("dry", "kept"),
                                Set.of("rule-1"),
                                Set.of("dry", "kept", "orphan")));

        Assert.assertEquals(List.of("dry"), plan.rulelessDetectors());
        Assert.assertEquals(List.of("orphan"), plan.ownerlessDetectors());
        Assert.assertEquals(List.of("dry", "orphan"), plan.detectors());
    }

    /** With only one kind present, the other count is zero rather than absent. */
    public void testPlan_countsZeroForTheKindThatIsNotThere() {
        StandardSpaceReconciler.Plan soloSinReglas =
                StandardSpaceReconciler.plan(
                        inventory(
                                Map.of("dry", List.of("gone-rule")),
                                Set.of(),
                                Set.of("dry"),
                                Set.of(),
                                Set.of("dry")));

        Assert.assertEquals(List.of("dry"), soloSinReglas.rulelessDetectors());
        Assert.assertTrue(soloSinReglas.ownerlessDetectors().isEmpty());
        Assert.assertEquals(List.of("dry"), soloSinReglas.detectors());
    }

    // --- The deletions ----------------------------------------------------------------------

    /**
     * The order is load-bearing: the detector goes before the rules it points at, so the detection
     * stops first, and the rules go before the integration, so the log type is not refused while they
     * are still there.
     */
    public void testApply_deletesDetectorsThenRulesThenIntegrations() {
        stubDeletionsSucceeding();
        StandardSpaceReconciler reconciler = new StandardSpaceReconciler(this.client, this.sapService);

        StandardSpaceReconciler.Result result =
                reconciler.apply(
                        new StandardSpaceReconciler.Plan(
                                List.of("detector-1"),
                                Collections.emptyList(),
                                List.of("rule-1", "rule-2"),
                                List.of("integration-1")));

        Assert.assertEquals(
                List.of("detector:detector-1", "rule:rule-1", "rule:rule-2", "integration:integration-1"),
                this.calls);
        Assert.assertTrue("nothing should be pending", result.pending().isEmpty());
        Assert.assertEquals(1, result.deletedDetectors());
        Assert.assertEquals(2, result.deletedRules());
        Assert.assertEquals(1, result.deletedIntegrations());
    }

    /** Only the standard space is ever touched. */
    public void testApply_onlyEverDeletesFromTheStandardSpace() {
        stubDeletionsSucceeding();
        StandardSpaceReconciler reconciler = new StandardSpaceReconciler(this.client, this.sapService);

        reconciler.apply(
                new StandardSpaceReconciler.Plan(
                        Collections.emptyList(),
                        Collections.emptyList(),
                        List.of("rule-1"),
                        List.of("integration-1")));

        verify(this.sapService).deleteRule(eq("rule-1"), eq(Space.STANDARD), any());
        verify(this.sapService).deleteIntegration(eq("integration-1"), eq(Space.STANDARD), any());
        for (Space space : Space.values()) {
            if (space != Space.STANDARD) {
                verify(this.sapService, never()).deleteRule(anyString(), eq(space), any());
                verify(this.sapService, never()).deleteIntegration(anyString(), eq(space), any());
            }
        }
    }

    /**
     * C1: a deletion that failed is reported as pending, and the resource is still left over, so the
     * next pass finds it again. No list of pending deletions is persisted anywhere.
     */
    public void testApply_aFailedDeletionIsReportedAsPending() {
        stubDeletionsSucceeding();
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<?>>getArgument(2)
                                    .onFailure(new IllegalStateException("index is read-only"));
                            return null;
                        })
                .when(this.sapService)
                .deleteRule(eq("rule-bad"), any(), any());
        StandardSpaceReconciler reconciler = new StandardSpaceReconciler(this.client, this.sapService);

        StandardSpaceReconciler.Result result =
                reconciler.apply(
                        new StandardSpaceReconciler.Plan(
                                Collections.emptyList(),
                                Collections.emptyList(),
                                List.of("rule-bad", "rule-ok"),
                                Collections.emptyList()));

        Assert.assertEquals(Set.of("rule-bad"), result.pending());
        Assert.assertEquals("the other rule still went", 1, result.deletedRules());
    }

    /** A failing deletion of one kind does not hold back the kinds after it. */
    public void testApply_aFailedDetectorDoesNotStopTheRest() {
        stubDeletionsSucceeding();
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<?>>getArgument(1)
                                    .onFailure(new IllegalStateException("no"));
                            return null;
                        })
                .when(this.sapService)
                .deleteDetector(eq("detector-bad"), any());
        StandardSpaceReconciler reconciler = new StandardSpaceReconciler(this.client, this.sapService);

        StandardSpaceReconciler.Result result =
                reconciler.apply(
                        new StandardSpaceReconciler.Plan(
                                List.of("detector-bad"),
                                Collections.emptyList(),
                                List.of("rule-1"),
                                List.of("integration-1")));

        Assert.assertEquals(Set.of("detector-bad"), result.pending());
        Assert.assertEquals(1, result.deletedRules());
        Assert.assertEquals(1, result.deletedIntegrations());
    }

    /**
     * A kind that left deletions running does not let the next kind start.
     *
     * <p>Security Analytics refuses to delete a log type while a detector still reads it, so an
     * integration whose detector is still being deleted would be reported as pending for a reason of
     * our own making. The ones already known to have failed are still reported, which is what asks
     * for the immediate retry.
     */
    public void testApply_aKindLeftInFlightStopsTheKindsAfterIt() {
        stubDeletionsSucceeding();
        // This detector never answers, so its kind is still in flight when the waits run out.
        doAnswer(invocation -> null).when(this.sapService).deleteDetector(eq("detector-silent"), any());
        StandardSpaceReconciler reconciler = new StandardSpaceReconciler(this.client, this.sapService);
        reconciler.setTimeoutsForTests(1, 1);

        StandardSpaceReconciler.Result result =
                reconciler.apply(
                        new StandardSpaceReconciler.Plan(
                                List.of("detector-silent"),
                                Collections.emptyList(),
                                List.of("rule-1"),
                                List.of("integration-1")));

        Assert.assertEquals(Set.of("detector-silent"), result.pending());
        Assert.assertEquals("the rules must not have started", 0, result.deletedRules());
        Assert.assertEquals("nor the integrations", 0, result.deletedIntegrations());
        verify(this.sapService, never()).deleteRule(anyString(), any(), any());
        verify(this.sapService, never()).deleteIntegration(anyString(), any(), any());
    }

    /**
     * A deletion that answered is not reported as pending when another one times out. Reporting it
     * would name resources that are already gone, count them as not deleted, and ask for a retry that
     * has nothing to do.
     */
    public void testApply_aTimeoutDoesNotReportTheOnesThatAnswered() {
        stubDeletionsSucceeding();
        // This one never answers: no response, no failure, so the latch never reaches zero.
        doAnswer(invocation -> null).when(this.sapService).deleteRule(eq("rule-silent"), any(), any());
        StandardSpaceReconciler reconciler = new StandardSpaceReconciler(this.client, this.sapService);
        // Without this the test sits out the production waits, which are two minutes and then five.
        reconciler.setTimeoutsForTests(1, 1);

        StandardSpaceReconciler.Result result =
                reconciler.apply(
                        new StandardSpaceReconciler.Plan(
                                Collections.emptyList(),
                                Collections.emptyList(),
                                List.of("rule-ok", "rule-silent"),
                                Collections.emptyList()));

        Assert.assertEquals(
                "only the one that never answered is pending", Set.of("rule-silent"), result.pending());
        Assert.assertEquals("the other one did go", 1, result.deletedRules());
    }

    // --- The guards -------------------------------------------------------------------------

    /**
     * A read that failed must never be taken for "the content is gone": acting on it would delete the
     * whole standard space from Security Analytics.
     */
    public void testReconcile_aFailedReadDeletesNothing() {
        StandardSpaceReconciler.Result result = reconcilerFailingToRead().reconcile();

        Assert.assertTrue(result.pending().isEmpty());
        Assert.assertFalse(result.deletedAnything());
        verifyNoInteractions(this.sapService);
    }

    /**
     * Nor may an empty content side be. A cluster whose content has not loaded yet looks exactly like
     * one whose content was deleted, and the blast radius is the whole standard space, so the diff
     * does not run. A space emptied on purpose is cleared through {@code StandardSpaceWiper}, which
     * deletes both sides together.
     */
    public void testReconcile_noContentIntegrationsDeletesNothing() {
        StandardSpaceReconciler.Result result =
                reconcilerReading(
                                inventory(
                                        Collections.emptyMap(),
                                        Collections.emptySet(),
                                        Set.of("integration-1"),
                                        Set.of("rule-1"),
                                        Set.of("integration-1")))
                        .reconcile();

        Assert.assertFalse(result.deletedAnything());
        verifyNoInteractions(this.sapService);
    }

    /**
     * An empty rule set is not trusted either, although the integrations are there.
     *
     * <p>Standard rules do not all disappear at once in normal operation, and a half-restored index
     * looks exactly the same from here. Acting on it would delete every standard rule from Security
     * Analytics and every detector with them, because an integration whose rules are all gone loses
     * its detector. The reconciliation would rather leave the leftovers for a pass that can read a
     * rule set.
     */
    public void testReconcile_noContentRulesDeletesNothing() {
        StandardSpaceReconciler.Result result =
                reconcilerReading(
                                inventory(
                                        Map.of("integration-1", List.of("rule-1")),
                                        Collections.emptySet(),
                                        Set.of("integration-1"),
                                        Set.of("rule-1"),
                                        Set.of("integration-1")))
                        .reconcile();

        Assert.assertFalse(result.deletedAnything());
        verifyNoInteractions(this.sapService);
    }

    /** With nothing on the Security Analytics side either, the guard still abstains. */
    public void testReconcile_noRulesOnEitherSideIsNotAFailure() {
        StandardSpaceReconciler.Result result =
                reconcilerReading(
                                inventory(
                                        Map.of("integration-1", Collections.emptyList()),
                                        Collections.emptySet(),
                                        Set.of("integration-1"),
                                        Collections.emptySet(),
                                        Collections.emptySet()))
                        .reconcile();

        Assert.assertFalse(result.deletedAnything());
        Assert.assertTrue(result.pending().isEmpty());
    }

    /**
     * The guard abstains on an empty content rule set whatever Security Analytics holds.
     *
     * <p>It used to require Security Analytics to still hold rules, which left the worst case open:
     * with both rule sets empty and detectors present, every integration reads as having lost all of
     * its rules and every standard detector is planned for deletion. The Security Analytics side is
     * read leniently, so an index that is absent or unreadable arrives here as an empty set.
     */
    public void testReconcile_emptyContentRulesSparesTheDetectorsWithNothingOnTheOtherSideEither() {
        StandardSpaceReconciler.Result result =
                reconcilerReading(
                                inventory(
                                        Map.of("integration-1", List.of("rule-1"), "integration-2", List.of("rule-2")),
                                        Collections.emptySet(),
                                        Set.of("integration-1", "integration-2"),
                                        Collections.emptySet(),
                                        Set.of("integration-1", "integration-2")))
                        .reconcile();

        Assert.assertFalse("no detector may be deleted here", result.deletedAnything());
        Assert.assertTrue(result.pending().isEmpty());
        verifyNoInteractions(this.sapService);
    }

    /** Both sides agreeing costs nothing beyond the reads. */
    public void testReconcile_nothingStaleTouchesNothing() {
        StandardSpaceReconciler.Result result =
                reconcilerReading(
                                inventory(
                                        Map.of("integration-1", List.of("rule-1")),
                                        Set.of("rule-1"),
                                        Set.of("integration-1"),
                                        Set.of("rule-1"),
                                        Set.of("integration-1")))
                        .reconcile();

        Assert.assertFalse(result.deletedAnything());
        Assert.assertTrue(result.pending().isEmpty());
        verifyNoInteractions(this.sapService);
    }
}
