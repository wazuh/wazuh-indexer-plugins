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
import org.opensearch.action.get.GetResponse;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.AbstractConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerCveService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerIocService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerRulesetService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.jobscheduler.JobExecutor;
import com.wazuh.contentmanager.utils.Constants;

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

    private final Client client;
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
     * @param engineService The engine service for notifying the Engine about IOC updates.
     */
    public CatalogSyncJob(
            Client client,
            ConsumersIndex consumersIndex,
            Environment environment,
            ThreadPool threadPool,
            EngineService engineService) {
        this.client = client;
        this.threadPool = threadPool;
        this.synchronizers =
                List.of(
                        new ConsumerRulesetService(client, consumersIndex, environment, engineService),
                        new ConsumerIocService(client, consumersIndex, environment, engineService),
                        new ConsumerCveService(client, consumersIndex, environment));
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
                                log.debug("Executing Consumer Sync Job (ID: {})", context.getJobId());
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
                                this.performSynchronization();
                            } catch (Exception e) {
                                log.error("Error running CatalogSyncJob: {}", e.getMessage(), e);
                            } finally {
                                this.semaphore.release();
                            }
                        });
    }

    /**
     * Centralized synchronization logic used by both execute() and trigger(). Waits for the Setup
     * plugin to finish creating its indices before iterating through all registered synchronizers and
     * executing them. If the Setup plugin does not complete in time, the pass is skipped; the
     * periodic job will retry on its next scheduled run.
     */
    private void performSynchronization() {
        if (!this.waitForSetup()) {
            log.error(
                    "Setup plugin initialization did not complete in time. Skipping catalog"
                            + " synchronization; it will be retried on the next scheduled run.");
            return;
        }
        for (AbstractConsumerService synchronizer : this.synchronizers) {
            try {
                synchronizer.synchronize();
                log.debug("{} synchronized.", synchronizer.getClass().getSimpleName());
            } catch (Exception e) {
                log.error(
                        "Error during synchronization of {}: {}",
                        synchronizer.getClass().getSimpleName(),
                        e.getMessage(),
                        e);
            }
        }
    }

    /**
     * Blocks until the Setup plugin reports its initialization as complete via the {@value
     * Constants#SETUP_STATUS_DOC_ID} marker document in the {@value Constants#INDEX_SETUP_STATUS}
     * index. Retries up to {@link Constants#MAX_SETUP_WAIT_RETRIES} times with exponential backoff
     * (5s, 10s, 20s) before giving up. This method blocks the calling generic-pool thread for up to
     * 35 seconds in the worst case.
     *
     * @return true if the Setup plugin completed its initialization, false otherwise.
     */
    boolean waitForSetup() {
        for (int attempt = 0; ; attempt++) {
            if (this.isSetupComplete()) {
                return true;
            }
            if (attempt >= Constants.MAX_SETUP_WAIT_RETRIES) {
                return false;
            }
            long delaySeconds = Constants.SETUP_WAIT_BACKOFF_BASE_SECONDS * (1L << attempt);
            log.info(
                    "Setup plugin initialization not complete yet. Retrying in {}s (attempt {}/{}).",
                    delaySeconds,
                    attempt + 1,
                    Constants.MAX_SETUP_WAIT_RETRIES);
            try {
                TimeUnit.SECONDS.sleep(delaySeconds);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /**
     * Reads the Setup plugin's readiness marker. Any failure (index not created yet, cluster not
     * ready) is treated as "setup not complete".
     *
     * @return true if the marker document exists with status {@value
     *     Constants#SETUP_STATUS_COMPLETE}.
     */
    private boolean isSetupComplete() {
        try {
            GetResponse response =
                    this.client.prepareGet(Constants.INDEX_SETUP_STATUS, Constants.SETUP_STATUS_DOC_ID).get();
            if (!response.isExists()) {
                return false;
            }
            Map<String, Object> source = response.getSourceAsMap();
            return source != null
                    && Constants.SETUP_STATUS_COMPLETE.equals(source.get(Constants.KEY_STATUS));
        } catch (Exception e) {
            log.debug("Could not read setup status marker: {}", e.getMessage());
            return false;
        }
    }
}
