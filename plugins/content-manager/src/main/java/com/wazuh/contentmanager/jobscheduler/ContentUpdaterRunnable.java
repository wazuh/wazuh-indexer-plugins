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
import org.opensearch.client.Client;
import org.opensearch.env.Environment;
import org.opensearch.threadpool.ThreadPool;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.updater.ContentUpdater;
import com.wazuh.contentmanager.utils.SnapshotHelper;

/** Runnable class for the Content Updater job. */
public class ContentUpdaterRunnable implements Runnable {
    private static final Logger log = LogManager.getLogger(ContentUpdaterRunnable.class);
    private final Client client;
    private final ThreadPool threadPool;
    private final Environment environment;
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;

    /**
     * Default constructor.
     *
     * @param client OpenSearch's client.
     * @param threadPool ThreadPool to run the job.
     * @param environment Environment to run the job.
     * @param contextIndex ContextIndex to run the job.
     * @param contentIndex ContentIndex to run the job.
     */
    public ContentUpdaterRunnable(
            Client client,
            ThreadPool threadPool,
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex) {
        this.client = client;
        this.threadPool = threadPool;
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
    }

    @Override
    public void run() {
        CTIClient ctiClient = CTIClient.getInstance();
        ConsumerInfo newConsumerInfo = ctiClient.getCatalog();

        if (this.contextIndex.getOffset() == 0L) {
            SnapshotHelper snapshotHelper =
                    new SnapshotHelper(threadPool, environment, contextIndex, contentIndex);
            snapshotHelper.initialize();
        } else if (this.contextIndex.getOffset() == newConsumerInfo.getLastOffset()) {
            log.info("No new content to index.");
            return;
        } else if (this.contextIndex.getOffset() < newConsumerInfo.getLastOffset()) {
            ContentUpdater contentUpdater = new ContentUpdater(ctiClient, contextIndex, contentIndex);
            contentUpdater.update();
        }
    }
}
