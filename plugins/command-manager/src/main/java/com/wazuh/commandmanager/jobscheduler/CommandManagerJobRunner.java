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
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.threadpool.ThreadPool;

import com.wazuh.commandmanager.CommandManagerPlugin;

/**
 * Implements the ScheduledJobRunner interface, which exposes the runJob() method, which executes
 * the job's logic in its own thread.
 */
public class CommandManagerJobRunner implements ScheduledJobRunner {

    private static final Logger log = LogManager.getLogger(CommandManagerJobRunner.class);
    private static CommandManagerJobRunner INSTANCE;
    private ThreadPool threadPool;
    private ClusterService clusterService;

    private Client client;
    private Environment environment;

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

    private boolean commandManagerIndexExists() {
        return this.clusterService
                .state()
                .routingTable()
                .hasIndex(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
    }

    @Override
    public void runJob(ScheduledJobParameter jobParameter, JobExecutionContext context) {
        if (!commandManagerIndexExists()) {
            log.info(
                    "{} index not yet created, not running command manager jobs",
                    CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
            return;
        }
        SearchThread searchThread = new SearchThread(this.client);
        threadPool.generic().submit(searchThread);
    }

    public CommandManagerJobRunner setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
        return getInstance();
    }

    public CommandManagerJobRunner setClient(Client client) {
        this.client = client;
        return getInstance();
    }

    public CommandManagerJobRunner setEnvironment(Environment environment) {
        this.environment = environment;
        return getInstance();
    }

    public CommandManagerJobRunner setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
        return getInstance();
    }
}
