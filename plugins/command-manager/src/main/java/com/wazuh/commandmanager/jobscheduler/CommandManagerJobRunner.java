/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.threadpool.ThreadPool;

import com.wazuh.commandmanager.CommandManagerPlugin;

public class CommandManagerJobRunner implements ScheduledJobRunner {

    private static final Logger log = LogManager.getLogger(CommandManagerJobRunner.class);
    private static CommandManagerJobRunner INSTANCE;
    private ThreadPool threadPool;
    private ClusterService clusterService;

    private Client client;
    private final SearchJob searchJob = SearchJob.getInstance();

    private CommandManagerJobRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public static CommandManagerJobRunner getInstance() {
        log.info("Getting Job Runner Instance");
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (CommandManagerJobRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new CommandManagerJobRunner();
            return INSTANCE;
        }
    }

    private boolean indexExists(String indexName) {
        return this.clusterService.state().routingTable().hasIndex(indexName);
    }

    @Override
    public void runJob(ScheduledJobParameter jobParameter, JobExecutionContext context) {
        if (!indexExists(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)) {
            log.info(
                "{} index not yet created, not running command manager jobs",
                CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
            return;
        }
        threadPool.generic()
            .submit(
                this.searchJob.searchJobRunnable(
                    this.client,
                    CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME,
                    CommandManagerPlugin.PAGE_SIZE
                )
            );
    }

    public void setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public Client getClient() {
        return client;
    }

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }
}
