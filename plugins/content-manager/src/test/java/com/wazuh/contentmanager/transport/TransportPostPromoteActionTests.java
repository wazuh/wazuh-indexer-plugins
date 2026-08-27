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
package com.wazuh.contentmanager.transport;

import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.service.DetectorLookupService.DetectorRules;

/** Unit tests for the rejection message built by {@link TransportPostPromoteAction}. */
public class TransportPostPromoteActionTests extends OpenSearchTestCase {

    private static DetectorRules detector(String name, String... ruleIds) {
        return new DetectorRules(name, name, true, List.of(ruleIds));
    }

    /** Nothing would be emptied, so the promotion proceeds. */
    public void testNoRejectionWhenEveryDetectorKeepsARule() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("keeps-one", "a", "b")),
                        Map.of("a", true, "b", true),
                        Map.of("a", false),
                        Set.of());

        assertNull(message);
    }

    /** A single emptied detector keeps the singular wording, naming the rule and the detector. */
    public void testSingleDetectorIsNamedWithItsRule() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("critical", "a")), Map.of("a", true), Map.of("a", false), Set.of());

        assertNotNull(message);
        assertTrue(message, message.contains("detector [critical]"));
        assertTrue(message, message.contains("Rule [a]"));
        assertFalse(message, message.contains("detectors"));
    }

    /**
     * A promotion carrying several rule changes can empty several detectors at once, each through a
     * different rule. All of them must be reported, so the user is not left fixing one per attempt.
     */
    public void testEveryEmptiedDetectorIsReportedWithItsOwnRule() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("config-critical", "a"), detector("audit-critical", "b")),
                        Map.of("a", true, "b", true),
                        Map.of("a", false, "b", false),
                        Set.of());

        assertNotNull(message);
        assertTrue(message, message.contains("2 detectors"));
        assertTrue(message, message.contains("[audit-critical] by disabling rule [b]"));
        assertTrue(message, message.contains("[config-critical] by disabling rule [a]"));
    }

    /** Detectors that survive the promotion are left out of the message. */
    public void testSurvivingDetectorsAreNotReported() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("survives", "a", "b"), detector("emptied", "a")),
                        Map.of("a", true, "b", true),
                        Map.of("a", false),
                        Set.of());

        assertNotNull(message);
        assertTrue(message, message.contains("detector [emptied]"));
        assertFalse(message, message.contains("survives"));
    }

    /**
     * The listing is ordered by detector name, so the same promotion always reports the same text.
     */
    public void testListingIsDeterministic() {
        List<DetectorRules> oneOrder = List.of(detector("zeta", "a"), detector("alpha", "b"));
        List<DetectorRules> otherOrder = List.of(detector("alpha", "b"), detector("zeta", "a"));
        Map<String, Boolean> current = Map.of("a", true, "b", true);
        Map<String, Boolean> incoming = Map.of("a", false, "b", false);

        assertEquals(
                TransportPostPromoteAction.rejectionMessage(oneOrder, current, incoming, Set.of()),
                TransportPostPromoteAction.rejectionMessage(otherOrder, current, incoming, Set.of()));
    }

    /** A removal is reported as the culprit just like a disable. */
    public void testRemovedRuleIsReportedAsTheCulprit() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("critical", "a")), Map.of("a", true), Map.of(), Set.of("a"));

        assertNotNull(message);
        assertTrue(message, message.contains("Rule [a]"));
        assertTrue(message, message.contains("detector [critical]"));
    }
}
