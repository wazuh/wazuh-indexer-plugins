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

import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** Unit tests for {@link DetectorRuleGuard}. */
public class DetectorRuleGuardTests extends OpenSearchTestCase {

    /** Disabling one rule out of three leaves two enabled: allowed. */
    public void testAllowsWhenOtherRulesStayEnabled() {
        assertFalse(
                DetectorRuleGuard.wouldLeaveDetectorEmpty(
                        List.of("a", "b", "c"),
                        Map.of("a", true, "b", true, "c", true),
                        Map.of("a", false),
                        Set.of()));
    }

    /** Disabling the only enabled rule empties the detector: blocked. */
    public void testBlocksWhenLastEnabledRuleIsDisabled() {
        assertTrue(
                DetectorRuleGuard.wouldLeaveDetectorEmpty(
                        List.of("a", "b"), Map.of("a", true, "b", false), Map.of("a", false), Set.of()));
    }

    /** An update that does not change the enabled flag must not block. */
    public void testAllowsUpdateThatKeepsRuleEnabled() {
        assertFalse(
                DetectorRuleGuard.wouldLeaveDetectorEmpty(
                        List.of("a", "b"), Map.of("a", true, "b", false), Map.of("a", true), Set.of()));
    }

    /** Disabling one rule while enabling another in the same promotion is allowed. */
    public void testAllowsSwapWithinSamePromotion() {
        assertFalse(
                DetectorRuleGuard.wouldLeaveDetectorEmpty(
                        List.of("a", "b"),
                        Map.of("a", true, "b", false),
                        Map.of("a", false, "b", true),
                        Set.of()));
    }

    /** A detector already without enabled rules is not made worse: allowed. */
    public void testAllowsWhenDetectorWasAlreadyEmpty() {
        assertFalse(
                DetectorRuleGuard.wouldLeaveDetectorEmpty(
                        List.of("a", "b"), Map.of("a", false, "b", false), Map.of("a", false), Set.of()));
    }

    /** Removing the only enabled rule empties the detector: blocked. */
    public void testBlocksWhenLastEnabledRuleIsRemoved() {
        assertTrue(
                DetectorRuleGuard.wouldLeaveDetectorEmpty(
                        List.of("a", "b"), Map.of("a", true, "b", false), Map.of(), Set.of("a")));
    }

    /** A rule with no recorded state counts as disabled, never as a phantom enabled rule. */
    public void testTreatsUnknownRuleStateAsDisabled() {
        assertTrue(
                DetectorRuleGuard.wouldLeaveDetectorEmpty(
                        List.of("a", "ghost"), Map.of("a", true), Map.of("a", false), Set.of()));
    }
}
