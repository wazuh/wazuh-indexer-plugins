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

import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.threadpool.ThreadPool;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.utils.Privileged;

/** Class to run the Content Updater job. */
public class ContentUpdaterJobRunner implements ScheduledJobRunner {

    /** Singleton instance. */
    private static ContentUpdaterJobRunner INSTANCE;

    private CTIClient client;
    private ThreadPool threadPool;
    private Environment environment;
    private ContentIndex contentIndex;
    private ContextIndex contextIndex;
    private Privileged privileged;

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
     * @param environment OpenSearch's environment.
     * @param contextIndex Handles context and consumer related metadata.
     * @param contentIndex Handles indexed content.
     * @param privileged Handles privileged operations.
     * @return the singleton instance.
     */
    public static ContentUpdaterJobRunner getInstance(
            CTIClient client,
            ThreadPool threadPool,
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex,
            Privileged privileged) {
        if (ContentUpdaterJobRunner.INSTANCE == null) {
            INSTANCE = new ContentUpdaterJobRunner();
        }
        INSTANCE.setPrivileged(privileged);
        INSTANCE.setClient(client);
        INSTANCE.setThreadPool(threadPool);
        INSTANCE.setContextIndex(contextIndex);
        INSTANCE.setContentIndex(contentIndex);
        INSTANCE.setEnvironment(environment);
        return INSTANCE;
    }

    @Override
    public void runJob(
            ScheduledJobParameter scheduledJobParameter, JobExecutionContext jobExecutionContext) {
        ContentUpdaterRunnable jobRunnable =
                new ContentUpdaterRunnable(
                        this.threadPool,
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.client,
                        this.privileged);
        this.threadPool.generic().submit(jobRunnable);
    }

    /**
     * Sets the privileged object
     *
     * @param privileged Handles privileged operations.
     */
    public void setPrivileged(Privileged privileged) {
        this.privileged = privileged;
    }

    /**
     * Sets the client.
     *
     * @param client OpenSearch's client.
     */
    public void setClient(CTIClient client) {
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

    /**
     * Sets the context index.
     *
     * @param contextIndex Handles context and consumer related metadata.
     */
    public void setContextIndex(ContextIndex contextIndex) {
        this.contextIndex = contextIndex;
    }

    /**
     * Sets the environment.
     *
     * @param environment OpenSearch's environment.
     */
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    /**
     * Sets the content index.
     *
     * @param contentIndex Handles indexed content.
     */
    public void setContentIndex(ContentIndex contentIndex) {
        this.contentIndex = contentIndex;
    }
}
