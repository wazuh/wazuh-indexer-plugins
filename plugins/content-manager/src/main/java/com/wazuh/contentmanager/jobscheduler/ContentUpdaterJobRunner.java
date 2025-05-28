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
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.utils.Privileged;

/** Class to run the Content Updater job. */
public final class ContentUpdaterJobRunner implements ScheduledJobRunner {

    /** Singleton instance. */
    private static ContentUpdaterJobRunner INSTANCE;

    private CTIClient ctiClient;
    private ThreadPool threadPool;
    private Environment environment;
    private ContentIndex contentIndex;
    private ContextIndex contextIndex;
    private Privileged privileged;
    private CommandManagerClient commandManagerClient;

    /** Private default constructor for ContentUpdaterJobRunner. */
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

    @Override
    public void runJob(
            ScheduledJobParameter scheduledJobParameter, JobExecutionContext jobExecutionContext) {
        if (this.commandManagerClient == null) {
            this.commandManagerClient =
                    this.privileged.doPrivilegedRequest(CommandManagerClient::getInstance);
        }
        ContentUpdaterRunnable jobRunnable =
                ContentUpdaterRunnable.getInstance(
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.ctiClient,
                        this.privileged,
                        this.commandManagerClient);
        this.threadPool.generic().submit(jobRunnable);
    }

    /**
     * Sets the CTI client.
     *
     * @param ctiClient CTIClient to interact with the CTI API.
     * @return the ContentUpdaterJobRunner instance.
     */
    public ContentUpdaterJobRunner setCtiClient(CTIClient ctiClient) {
        this.ctiClient = ctiClient;
        return this;
    }

    /**
     * Sets the thread pool.
     *
     * @param threadPool OpenSearch's thread pool.
     * @return the ContentUpdaterJobRunner instance.
     */
    public ContentUpdaterJobRunner setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
        return this;
    }

    /**
     * Sets the environment.
     *
     * @param environment OpenSearch's environment.
     * @return the ContentUpdaterJobRunner instance.
     */
    public ContentUpdaterJobRunner setEnvironment(Environment environment) {
        this.environment = environment;
        return this;
    }

    /**
     * Sets the context index.
     *
     * @param contextIndex Handles context and consumer related metadata.
     * @return the ContentUpdaterJobRunner instance.
     */
    public ContentUpdaterJobRunner setContextIndex(ContextIndex contextIndex) {
        this.contextIndex = contextIndex;
        return this;
    }

    /**
     * Sets the content index.
     *
     * @param contentIndex Handles indexed content.
     * @return the ContentUpdaterJobRunner instance.
     */
    public ContentUpdaterJobRunner setContentIndex(ContentIndex contentIndex) {
        this.contentIndex = contentIndex;
        return this;
    }

    /**
     * Sets the privileged object.
     *
     * @param privileged Handles privileged operations.
     * @return the ContentUpdaterJobRunner instance.
     */
    public ContentUpdaterJobRunner setPrivileged(Privileged privileged) {
        this.privileged = privileged;
        return this;
    }

    /**
     * Sets the command manager client.
     *
     * @param commandManagerClient CommandManagerClient to interact with the command manager API.
     * @return the ContentUpdaterJobRunner instance.
     */
    public ContentUpdaterJobRunner setCommandManagerClient(
            CommandManagerClient commandManagerClient) {
        this.commandManagerClient = commandManagerClient;
        return this;
    }
}
