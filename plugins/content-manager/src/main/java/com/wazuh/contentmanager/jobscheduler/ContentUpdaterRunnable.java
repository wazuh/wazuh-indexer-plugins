/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.env.Environment;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.cti.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.updater.ContentUpdater;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.SnapshotManager;

/** Runnable class for the Content Updater job. */
public final class ContentUpdaterRunnable implements Runnable {
    private static final Logger log = LogManager.getLogger(ContentUpdaterRunnable.class);
    private static ContentUpdaterRunnable INSTANCE;
    private final Privileged privileged;
    private final Environment environment;
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;
    private final CTIClient ctiClient;
    private final CommandManagerClient commandManagerClient;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);

    /**
     * Default constructor.
     *
     * @param environment Environment to run the job.
     * @param contextIndex ContextIndex to run the job.
     * @param contentIndex ContentIndex to run the job.
     * @param ctiClient CTIClient to interact with the CTI API.
     * @param privileged Privileged to run the job.
     */
    private ContentUpdaterRunnable(
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex,
            CTIClient ctiClient,
            Privileged privileged) {
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
        this.ctiClient = ctiClient;
        this.privileged = privileged;
        // The Command Manager client needs the cluster to be up (depends on PluginSettings),
        // so we initialize it here once the node is up and ready.
        this.commandManagerClient =
                this.privileged.doPrivilegedRequest(CommandManagerClient::getInstance);
    }

    /**
     * Singleton instance access method.
     *
     * @param environment the environment to pass to SnapshotManager
     * @param contextIndex handles the context and consumer related metadata
     * @param contentIndex handles the indexed content
     * @param ctiClient the CTIClient to interact with the CTI API
     * @param privileged handles privileged operations
     * @return the singleton instance
     */
    public static ContentUpdaterRunnable getInstance(
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex,
            CTIClient ctiClient,
            Privileged privileged) {
        if (INSTANCE == null) {
            INSTANCE =
                    new ContentUpdaterRunnable(
                            environment, contextIndex, contentIndex, ctiClient, privileged);
        }
        return INSTANCE;
    }

    @Override
    public void run() {
        if (!this.isRunning.compareAndSet(false, true)) {
            log.warn("Content Updater job is already running.");
            return;
        }
        ConsumerInfo latest = privileged.getConsumerInfo(this.ctiClient);
        long latestOffset = latest.getLastOffset();

        try {
            ConsumerInfo current =
                    this.contextIndex.get(
                            PluginSettings.getInstance().getContextId(),
                            PluginSettings.getInstance().getConsumerId());
            long currentOffset = current.getOffset();
            if (currentOffset == 0L) {
                SnapshotManager snapshotManager =
                        new SnapshotManager(
                                this.environment,
                                this.contextIndex,
                                this.contentIndex,
                                this.privileged,
                                this.ctiClient);
                snapshotManager.initialize(latest);
            } else if (currentOffset < latestOffset) {
                ContentUpdater contentUpdater =
                        new ContentUpdater(
                                this.ctiClient,
                                this.commandManagerClient,
                                this.contextIndex,
                                this.contentIndex,
                                this.privileged);
                contentUpdater.update(current, latestOffset);
            } else if (currentOffset == latestOffset) {
                log.info(
                        "Consumer is up-to-date (offset {} == {}). Skipping...", currentOffset, latestOffset);
            }
        } catch (IOException e) {
            log.error("Failed to run Content Updater job: {}", e.getMessage());
        } finally {
            this.isRunning.set(false);
        }
    }
}
