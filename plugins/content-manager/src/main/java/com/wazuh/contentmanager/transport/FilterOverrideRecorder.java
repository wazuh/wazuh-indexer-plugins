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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;

import java.util.function.UnaryOperator;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Shared tail end of the three filter actions' registry bookkeeping.
 *
 * <p>Creating, updating and deleting a filter each live in a different transport hierarchy, but all
 * three need the same two decisions afterwards: skip every space but {@code standard}, and never
 * let a registry problem fail a request that has already succeeded.
 */
final class FilterOverrideRecorder {

    private static final Logger log = LogManager.getLogger(FilterOverrideRecorder.class);

    private FilterOverrideRecorder() {}

    /**
     * Applies {@code mutator} to the standard space's stored overrides, then runs {@code onDone}.
     *
     * <p>Other spaces are skipped outright: {@code draft}, {@code test} and {@code custom} are never
     * rebuilt from CTI, so their filters survive a sync without any help.
     *
     * <p>A registry failure is logged and swallowed. By the time this runs the filter itself has been
     * written, unlinked or deleted, and the space hash recalculated -- the user's request did
     * succeed. The cost of the failure is that this filter will not survive the next rebuild, which
     * the log message says explicitly.
     *
     * @param userOverridesService the registry.
     * @param spaceName the space the filter operation happened in.
     * @param mutator what to change in the registry, from {@link UserOverridesService#storeFilter} or
     *     {@link UserOverridesService#removeFilter}.
     * @param filterId the filter's document id, for the log message.
     * @param onDone run once, whatever the outcome, to answer the request.
     */
    static void record(
            UserOverridesService userOverridesService,
            String spaceName,
            UnaryOperator<UserOverrides> mutator,
            String filterId,
            Runnable onDone) {
        if (!Space.STANDARD.equals(spaceName)) {
            onDone.run();
            return;
        }

        userOverridesService.update(
                spaceName,
                mutator,
                ActionListener.wrap(
                        v -> onDone.run(),
                        e -> {
                            log.warn(
                                    Constants.W_LOG_USER_OVERRIDES_FILTER_RECORD_FAILED, filterId, e.getMessage());
                            onDone.run();
                        }));
    }
}
