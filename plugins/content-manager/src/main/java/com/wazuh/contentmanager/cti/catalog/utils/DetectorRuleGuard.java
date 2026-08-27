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

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Decides whether promoting a set of rule changes would leave a detector with no enabled rules.
 *
 * <p>A detector compiles its enabled rules into an alerting monitor. If every rule it references
 * ends up disabled, the monitor is removed and the detector stops producing findings while still
 * appearing configured. This guard lets the promotion be rejected before that happens.
 */
public final class DetectorRuleGuard {

    private DetectorRuleGuard() {}

    /**
     * Returns whether the promotion would take a detector from having at least one enabled rule to
     * having none. A detector that already had none is not considered, since the promotion does not
     * make its situation worse.
     *
     * @param detectorRuleIds the rule ids referenced by the detector.
     * @param currentEnabled enabled state of those rules in the target space, before the promotion. A
     *     missing entry counts as disabled.
     * @param incomingEnabled enabled state carried by the promotion, keyed by rule id. Only contains
     *     the rules included in the changeset.
     * @param removedRuleIds rule ids the promotion deletes.
     * @return {@code true} when the promotion must be rejected for this detector.
     */
    public static boolean wouldLeaveDetectorEmpty(
            List<String> detectorRuleIds,
            Map<String, Boolean> currentEnabled,
            Map<String, Boolean> incomingEnabled,
            Set<String> removedRuleIds) {

        long before =
                detectorRuleIds.stream().filter(id -> Boolean.TRUE.equals(currentEnabled.get(id))).count();
        if (before == 0) {
            return false;
        }

        long after =
                detectorRuleIds.stream()
                        .filter(id -> !removedRuleIds.contains(id))
                        .filter(
                                id ->
                                        incomingEnabled.containsKey(id)
                                                ? Boolean.TRUE.equals(incomingEnabled.get(id))
                                                : Boolean.TRUE.equals(currentEnabled.get(id)))
                        .count();

        return after == 0;
    }
}
