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

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.NodeShutdown;

/**
 * The {@link ContentWiper} of the ruleset consumer: it deletes the Standard space, and only the
 * Standard space.
 *
 * <p>The space's resources are removed from Security Analytics first and its documents from the
 * content indices second, the same two steps and the same order a resync has always used. Both
 * select by space, so the Draft, Test and Custom spaces are untouched, and so is the user overrides
 * registry: that document deliberately carries no space field, which is what keeps a wipe from
 * deleting the user's own settings, filters and disabled integrations.
 *
 * <p>None of this is a transaction. A failure in the content deletion leaves Security Analytics
 * already emptied, and that deletion is itself one bulk across the six content indices, so an index
 * that refuses its deletes does not undo the ones the others already took: what is left is neither
 * the old Standard space nor the new one. A timeout abandons a deletion the cluster may still
 * finish on its own. A {@code false} therefore says only that the space was not confirmed empty,
 * which is what a load needs before writing over it; it promises nothing about what is still there.
 * The phases a content change owes are recorded before any of this runs, and a pass that loads
 * nothing asks for an immediate retry, so the space is rebuilt on the next pass rather than at the
 * next scheduled one.
 */
final class StandardSpaceWiper implements ContentWiper {

    private static final Logger log = LogManager.getLogger(StandardSpaceWiper.class);

    /**
     * How long to wait for each of the two deletions a wipe is made of. Longer than the plugin client
     * timeout on purpose: a deletion spans six indices and the resources Security Analytics built
     * from them, and giving up on it early is what leaves the space half empty.
     */
    private static final long TIMEOUT_SECONDS = 60;

    private final SecurityAnalyticsService securityAnalyticsService;
    private final SpaceService spaceService;
    private final String consumerType;

    /**
     * Builds the wiper over services the caller supplies, so it can be exercised without a cluster.
     *
     * @param securityAnalyticsService deletes the space's resources in Security Analytics.
     * @param spaceService deletes the space's documents in the content indices.
     * @param consumerType the consumer type, for the log message.
     */
    StandardSpaceWiper(
            SecurityAnalyticsService securityAnalyticsService,
            SpaceService spaceService,
            String consumerType) {
        this.securityAnalyticsService = securityAnalyticsService;
        this.spaceService = spaceService;
        this.consumerType = consumerType;
    }

    @Override
    public boolean wipe() {
        try {
            CompletableFuture<Void> securityAnalytics = new CompletableFuture<>();
            this.securityAnalyticsService.deleteSpaceResources(
                    Space.STANDARD,
                    ActionListener.wrap(
                            r -> securityAnalytics.complete(null), securityAnalytics::completeExceptionally));
            securityAnalytics.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

            CompletableFuture<Void> content = new CompletableFuture<>();
            this.spaceService.deleteSpaceResources(
                    Space.STANDARD,
                    ActionListener.wrap(r -> content.complete(null), content::completeExceptionally));
            content.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

            return true;
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            // toString and not getMessage: the two failures this is most likely to see, a timeout
            // and an interrupt, both carry no message, and this line is the only account of why
            // the snapshot was not loaded. A node on its way down fails here every time, so it is
            // logged at the level that stop is expected to produce.
            log.log(
                    NodeShutdown.levelFor(e, Level.ERROR),
                    Constants.E_LOG_CLEAR_RESOURCES_FAILED,
                    this.consumerType,
                    e.toString());
            return false;
        }
    }
}
