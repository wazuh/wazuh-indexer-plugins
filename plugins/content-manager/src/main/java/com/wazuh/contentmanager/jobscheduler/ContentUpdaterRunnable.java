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
import org.opensearch.threadpool.ThreadPool;

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
public class ContentUpdaterRunnable implements Runnable {
    private static final Logger log = LogManager.getLogger(ContentUpdaterRunnable.class);
    private final Privileged privileged;
    private final ThreadPool threadPool;
    private final Environment environment;
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;
    private final CTIClient ctiClient;
    private final CommandManagerClient commandManagerClient;

    /**
     * Default constructor.
     *
     * @param threadPool ThreadPool to run the job.
     * @param environment Environment to run the job.
     * @param contextIndex ContextIndex to run the job.
     * @param contentIndex ContentIndex to run the job.
     * @param ctiClient CTIClient to interact with the CTI API.
     * @param privileged Privileged to run the job.
     */
    public ContentUpdaterRunnable(
            ThreadPool threadPool,
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex,
            CTIClient ctiClient,
            Privileged privileged) {
        this.threadPool = threadPool;
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

    @Override
    public void run() {
        ConsumerInfo newConsumerInfo = privileged.getConsumerInfo(this.ctiClient);

        ConsumerInfo current =
                this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID);
        if (current.getOffset() == 0L) {
            SnapshotManager snapshotManager =
                    new SnapshotManager(
                            this.environment, this.contextIndex, this.contentIndex, this.privileged);
            snapshotManager.initialize(newConsumerInfo);
        } else if (current.getOffset() == newConsumerInfo.getLastOffset()) {
            log.info("No new content to index.");
            return;
        } else if (current.getOffset() < newConsumerInfo.getLastOffset()) {
            ContentUpdater contentUpdater =
                    new ContentUpdater(
                            this.ctiClient,
                            this.commandManagerClient,
                            this.contextIndex,
                            this.contentIndex,
                            this.privileged);
            contentUpdater.update();
        }
    }
}
