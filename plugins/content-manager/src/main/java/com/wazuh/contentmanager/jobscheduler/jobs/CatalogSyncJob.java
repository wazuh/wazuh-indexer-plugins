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
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.AbstractConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerCveService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerIocService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerRulesetService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.jobscheduler.JobExecutor;
import com.wazuh.contentmanager.utils.SetupReadiness;

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

    /**
     * Tracks whether an immediate retry has already been fired for the current failure episode. Set
     * by {@link #handleOutcome(SyncOutcome)} on a fresh {@link SyncOutcome#FAILURE}; cleared on
     * {@link SyncOutcome#SUCCESS} or once the retry's own outcome has been evaluated. Guarantees at
     * most one immediate retry per failure episode.
     */
    private final AtomicBoolean retryPending = new AtomicBoolean(false);

    private final Client client;
    private final ThreadPool threadPool;
    private final List<AbstractConsumerService> synchronizers;
    private final SetupReadiness setupReadiness;

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
            EngineService engineService,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService) {
        this.client = client;
        this.setupReadiness = new SetupReadiness(client);
        this.threadPool = threadPool;
        this.synchronizers =
                List.of(
                        new ConsumerRulesetService(
                                client, consumersIndex, environment, spaceService, securityAnalyticsService),
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
        log.debug("Executing Consumer Sync Job (ID: {})", context.getJobId());
        this.threadPool.generic().execute(this::runSynchronizationPass);
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
        this.threadPool.generic().execute(this::runSynchronizationPass);
    }

    /**
     * Runs one synchronization pass and, once the semaphore has been released, hands the outcome to
     * {@link #handleOutcome(SyncOutcome)} so a failed pass can immediately trigger a single retry.
     * Shared by both {@link #execute(JobExecutionContext)} and {@link #trigger()}.
     */
    private void runSynchronizationPass() {
        SyncOutcome outcome = SyncOutcome.SETUP_NOT_READY;
        try {
            outcome = this.performSynchronization();
        } catch (Exception e) {
            log.error("Error running CatalogSyncJob: {}", e.getMessage(), e);
        } finally {
            this.semaphore.release();
        }
        // Must run after the semaphore is released, otherwise the retry's trigger() would find the
        // permit unavailable and silently no-op.
        this.handleOutcome(outcome);
    }

    /**
     * Reacts to the outcome of a synchronization pass. A fresh failure triggers exactly one immediate
     * retry via {@link #trigger()}; the retry's own outcome is evaluated the same way but the {@link
     * #retryPending} flag prevents it from triggering a second retry, so a persistently failing sync
     * falls back to waiting for the next scheduled run.
     *
     * @param outcome The result of the synchronization pass that just completed.
     */
    void handleOutcome(SyncOutcome outcome) {
        switch (outcome) {
            case SUCCESS -> this.retryPending.set(false);
            case FAILURE -> {
                if (this.retryPending.compareAndSet(false, true)) {
                    log.warn("Synchronization failed; triggering one immediate retry.");
                    this.trigger();
                } else {
                    log.error("Immediate retry also failed; waiting for the next scheduled run.");
                    this.retryPending.set(false);
                }
            }
            // waitForSetup() already retried internally; not a synchronization failure. Still clears
            // retryPending: if this was the immediate retry's own outcome, leaving the flag set would
            // cause the next unrelated FAILURE to be misread as that retry's outcome and skip its own
            // immediate retry.
            case SETUP_NOT_READY -> this.retryPending.set(false);
        }
    }

    /**
     * Reports whether an immediate retry is currently pending (i.e., the next {@link
     * SyncOutcome#FAILURE} evaluated will be treated as that retry's own outcome rather than a fresh
     * failure). Exposed for tests.
     *
     * @return true if a retry is pending, false otherwise.
     */
    boolean isRetryPending() {
        return this.retryPending.get();
    }

    /** The result of a single synchronization pass, used to decide whether to retry immediately. */
    enum SyncOutcome {
        SUCCESS,
        FAILURE,
        SETUP_NOT_READY
    }

    /**
     * Centralized synchronization logic used by both execute() and trigger(). Waits for the Setup
     * plugin to finish creating its indices before iterating through all registered synchronizers and
     * executing them. If the Setup plugin does not complete in time, the pass is skipped; the
     * periodic job will retry on its next scheduled run.
     *
     * @return {@link SyncOutcome#SETUP_NOT_READY} if the Setup plugin did not become ready in time,
     *     {@link SyncOutcome#FAILURE} if any synchronizer threw, {@link SyncOutcome#SUCCESS}
     *     otherwise.
     */
    private ThreadContext.StoredContext stashContext() {
        return this.threadPool.getThreadContext().stashContext();
    }

    SyncOutcome performSynchronization() {
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            if (!this.waitForSetup()) {
                log.error(
                        "Setup plugin initialization did not complete in time. Skipping catalog"
                                + " synchronization; it will be retried on the next scheduled run.");
                return SyncOutcome.SETUP_NOT_READY;
            }
            boolean anyFailure = false;
            for (AbstractConsumerService synchronizer : this.synchronizers) {
                try {
                    boolean feedUnreachable = synchronizer.synchronize();
                    if (feedUnreachable) {
                        // The synchronizer fell back to its local snapshot because the configured CTI
                        // feed was unreachable. Treat it as a failure so a single immediate retry fires;
                        // a transient network block then recovers without waiting for the next scheduled
                        // run.
                        anyFailure = true;
                        log.warn(
                                "{} could not reach its configured feed; content served from the local"
                                        + " snapshot.",
                                synchronizer.getClass().getSimpleName());
                    } else {
                        log.debug("{} synchronized.", synchronizer.getClass().getSimpleName());
                    }
                } catch (Exception e) {
                    anyFailure = true;
                    log.error(
                            "Error during synchronization of {}: {}",
                            synchronizer.getClass().getSimpleName(),
                            e.getMessage(),
                            e);
                }
            }
            return anyFailure ? SyncOutcome.FAILURE : SyncOutcome.SUCCESS;
        }
    }

    /**
     * Waits for the Setup plugin to finish initializing, so no catalog content is downloaded before
     * the indices it owns exist. Delegates to {@link SetupReadiness#awaitReady()}.
     *
     * @return true if the Setup plugin reported readiness, false otherwise.
     */
    boolean waitForSetup() {
        return this.setupReadiness.awaitReady();
    }
}
