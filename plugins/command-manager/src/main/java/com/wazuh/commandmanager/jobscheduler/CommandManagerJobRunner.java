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
