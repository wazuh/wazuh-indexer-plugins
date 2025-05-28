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
import org.opensearch.OpenSearchStatusException;
import org.opensearch.env.Environment;

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
    private Privileged privileged;
    private Environment environment;
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private CTIClient ctiClient;
    private CommandManagerClient commandManagerClient;
    private AtomicBoolean isRunning = new AtomicBoolean(false);
    private SnapshotManager snapshotManager;
    private ContentUpdater contentUpdater;

    private ContentUpdaterRunnable() {}

    /**
     * Singleton instance access method.
     *
     * @return the singleton instance
     */
    public static ContentUpdaterRunnable getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new ContentUpdaterRunnable();
        }
        return INSTANCE;
    }

    @Override
    public void run() {
        if (!this.isRunning.compareAndSet(false, true)) {
            log.debug("Content Updater job is already running.");
            return;
        }
        if (this.snapshotManager == null) {
            this.snapshotManager =
                    new SnapshotManager(
                            this.environment,
                            this.contextIndex,
                            this.contentIndex,
                            this.privileged,
                            this.ctiClient,
                            this.commandManagerClient);
        }
        if (this.contentUpdater == null) {
            this.contentUpdater =
                    new ContentUpdater(
                            this.ctiClient,
                            this.commandManagerClient,
                            this.contextIndex,
                            this.contentIndex,
                            this.privileged);
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
                this.snapshotManager.initialize(latest);
            } else if (currentOffset < latestOffset) {
                this.contentUpdater.update(current, latestOffset);
            } else if (currentOffset == latestOffset) {
                log.info(
                        "Consumer is up-to-date (offset {} == {}). Skipping...", currentOffset, latestOffset);
            }
        } catch (OpenSearchStatusException e) {
            log.error("Failed to run Content Updater job: {}", e.getMessage());
        } finally {
            this.isRunning.set(false);
        }
    }

    /**
     * Sets the privileged object for this runnable.
     *
     * @param privileged the privileged object to set
     */
    public ContentUpdaterRunnable setPrivileged(Privileged privileged) {
        this.privileged = privileged;
        return this;
    }

    /**
     * Sets the environment for this runnable.
     *
     * @param environment the environment to set
     */
    public ContentUpdaterRunnable setEnvironment(Environment environment) {
        this.environment = environment;
        return this;
    }

    /**
     * Sets the context index for this runnable.
     *
     * @param contextIndex the context index to set
     */
    public ContentUpdaterRunnable setContextIndex(ContextIndex contextIndex) {
        this.contextIndex = contextIndex;
        return this;
    }

    /**
     * Sets the content index for this runnable.
     *
     * @param contentIndex the content index to set
     */
    public ContentUpdaterRunnable setContentIndex(ContentIndex contentIndex) {
        this.contentIndex = contentIndex;
        return this;
    }

    /**
     * Sets the CTI client for this runnable.
     *
     * @param ctiClient the CTI client to set
     */
    public ContentUpdaterRunnable setCtiClient(CTIClient ctiClient) {
        this.ctiClient = ctiClient;
        return this;
    }

    /**
     * Sets the Command Manager client for this runnable.
     *
     * @param commandManagerClient the Command Manager client to set
     */
    public ContentUpdaterRunnable setCommandManagerClient(CommandManagerClient commandManagerClient) {
        this.commandManagerClient = commandManagerClient;
        return this;
    }

    /**
     * Sets the running state of this runnable.
     *
     * @param isRunning the AtomicBoolean to set
     */
    public ContentUpdaterRunnable setIsRunning(AtomicBoolean isRunning) {
        this.isRunning = isRunning;
        return this;
    }

    /**
     * Sets the SnapshotManager for this runnable.
     *
     * @param snapshotManager the SnapshotManager to set
     */
    public ContentUpdaterRunnable setSnapshotManager(SnapshotManager snapshotManager) {
        this.snapshotManager = snapshotManager;
        return this;
    }

    /**
     * Sets the ContentUpdater for this runnable.
     *
     * @param contentUpdater the ContentUpdater to set
     */
    public ContentUpdaterRunnable setContentUpdater(ContentUpdater contentUpdater) {
        this.contentUpdater = contentUpdater;
        return this;
    }
}
