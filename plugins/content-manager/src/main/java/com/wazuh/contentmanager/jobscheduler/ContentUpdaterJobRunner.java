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
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.threadpool.ThreadPool;

public class ContentUpdaterJobRunner implements ScheduledJobRunner {
    private static final Logger log = LogManager.getLogger(ContentUpdaterJobRunner.class);

    /** Singleton instance. */
    private static ContentUpdaterJobRunner INSTANCE;

    private Client client;
    private ThreadPool threadPool;

    /** Private default constructor. */
    private ContentUpdaterJobRunner() {}

    /**
     * Default Singleton instance access method.
     *
     * @return the singleton instance.
     */
    public static ContentUpdaterJobRunner getInstance() {
        if (ContentUpdaterJobRunner.INSTANCE == null) {
            INSTANCE = new ContentUpdaterJobRunner();
        }
        return INSTANCE;
    }

    /**
     * Singleton instance access method with parameters.
     *
     * @param client OpenSearch's client.
     * @param threadPool OpenSearch's thread pool.
     * @return the singleton instance.
     */
    public static ContentUpdaterJobRunner getInstance(Client client, ThreadPool threadPool) {
        if (ContentUpdaterJobRunner.INSTANCE == null) {
            INSTANCE = new ContentUpdaterJobRunner();
        }
        INSTANCE.setClient(client);
        INSTANCE.setThreadPool(threadPool);
        return INSTANCE;
    }

    @Override
    public void runJob(
            ScheduledJobParameter scheduledJobParameter, JobExecutionContext jobExecutionContext) {
        ContentUpdaterRunnable jobRunnable = new ContentUpdaterRunnable(this.client);
        this.threadPool.generic().submit(jobRunnable);
    }

    /**
     * Sets the client.
     *
     * @param client OpenSearch's client.
     */
    public void setClient(Client client) {
        this.client = client;
    }

    /**
     * Sets the thread pool.
     *
     * @param threadPool OpenSearch's thread pool.
     */
    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }
}
