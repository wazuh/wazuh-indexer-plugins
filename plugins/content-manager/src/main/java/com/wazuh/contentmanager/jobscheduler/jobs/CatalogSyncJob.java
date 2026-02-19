/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.jobscheduler.jobs;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.concurrent.Semaphore;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.AbstractConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerIocService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerRulesetService;
import com.wazuh.contentmanager.jobscheduler.JobExecutor;

/**
 * Job responsible for executing the synchronization logic for Rules and Decoders consumers. This
 * class handles only scheduling concerns and delegates synchronization to specialized classes.
 */
public class CatalogSyncJob implements JobExecutor {

    private static final Logger log = LogManager.getLogger(CatalogSyncJob.class);

    /** Identifier used to route this specific job type. */
    public static final String JOB_TYPE = "consumer-sync-task";

    /** Semaphore to control concurrency - only one job can run at a time. */
    private final Semaphore semaphore = new Semaphore(1);

    private final ThreadPool threadPool;
    private final List<AbstractConsumerService> synchronizers;

    /**
     * Constructs a new CatalogSyncJob.
     *
     * @param client The OpenSearch client used for administrative index operations.
     * @param consumersIndex The wrapper for accessing and managing the internal Consumers index.
     * @param environment The OpenSearch environment settings, used for path resolution.
     * @param threadPool The thread pool manager, used to offload blocking tasks to the generic
     *     executor.
     */
    public CatalogSyncJob(
            Client client,
            ConsumersIndex consumersIndex,
            Environment environment,
            ThreadPool threadPool) {
        this.threadPool = threadPool;
        this.synchronizers =
                List.of(
                        new ConsumerRulesetService(client, consumersIndex, environment),
                        new ConsumerIocService(client, consumersIndex, environment));
    }

    /**
     * Triggers the execution of the synchronization job via the Job Scheduler.
     *
     * @param context The execution context provided by the Job Scheduler, containing metadata like
     *     the Job ID.
     */
    @Override
    public void execute(JobExecutionContext context) {
        if (!this.semaphore.tryAcquire()) {
            log.warn(
                    "CatalogSyncJob (ID: {}) skipped because synchronization is already running.",
                    context.getJobId());
            return;
        }

        this.threadPool
                .generic()
                .execute(
                        () -> {
                            try {
                                log.info("Executing Consumer Sync Job (ID: {})", context.getJobId());
                                this.performSynchronization();
                            } catch (Exception e) {
                                log.error(
                                        "Error executing Consumer Sync Job (ID: {}): {}",
                                        context.getJobId(),
                                        e.getMessage(),
                                        e);
                            } finally {
                                this.semaphore.release();
                            }
                        });
    }

    /**
     * Checks if the synchronization job is currently running.
     *
     * @return true if running, false otherwise.
     */
    public boolean isRunning() {
        return this.semaphore.availablePermits() == 0;
    }

    /** Attempts to trigger the synchronization process manually. */
    public void trigger() {
        if (!this.semaphore.tryAcquire()) {
            log.warn("Attempted to trigger CatalogSyncJob manually while it is already running.");
            return;
        }

        this.threadPool
                .generic()
                .execute(
                        () -> {
                            try {
                                log.info("Executing Manually Triggered Consumer Sync Job");
                                this.performSynchronization();
                            } catch (Exception e) {
                                log.error("Error executing Manual Consumer Sync Job: {}", e.getMessage(), e);
                            } finally {
                                this.semaphore.release();
                            }
                        });
    }

    /**
     * Centralized synchronization logic used by both execute() and trigger(). Iterates through all
     * registered synchronizers and executes them.
     */
    private void performSynchronization() {
        for (AbstractConsumerService synchronizer : this.synchronizers) {
            try {
                synchronizer.synchronize();
                log.info("{} synchronized successfully.", synchronizer.getClass().getSimpleName());
            } catch (Exception e) {
                log.error(
                        "Error during synchronization of {}: {}",
                        synchronizer.getClass().getSimpleName(),
                        e.getMessage(),
                        e);
            }
        }
    }
}
