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
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.threadpool.Scheduler;
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
import com.wazuh.contentmanager.cti.catalog.service.ResourceLockService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.jobscheduler.JobExecutor;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.SetupReadiness;

/**
 * Job responsible for executing the synchronization logic for Rules and Decoders consumers. This
 * class handles only scheduling concerns and delegates synchronization to specialized classes.
 */
public class CatalogSyncJob implements JobExecutor {

    private static final Logger log = LogManager.getLogger(CatalogSyncJob.class);

    /** Identifier used to route this specific job type. */
    public static final String JOB_TYPE = "consumer-sync-task";

    /**
     * ID of the lock document, in {@link Constants#INDEX_RESOURCE_LOCKS}, that serializes the sync
     * across the cluster. The {@link #semaphore} only covers this node, and every node has its own:
     * without this lock the startup {@link #trigger()} on the cluster manager and the scheduled run
     * on another node can overlap, and both push the same detectors to Security Analytics.
     */
    static final String CLUSTER_LOCK_ID = "catalog-sync";

    /**
     * Time added to the stale threshold before the one startup retry, so a lock left behind by this
     * node is already stale when the retry asks for it.
     */
    static final long STARTUP_RETRY_MARGIN_MILLIS = 5_000L;

    /**
     * Delay between attempts to start the pass requested by a registration while another pass is
     * running.
     */
    static final long REGISTRATION_RETRY_DELAY_MILLIS = 30_000L;

    /**
     * Semaphore to control concurrency on this node - only one pass can run at a time. Held from
     * before the cluster lock is requested until after it is released.
     */
    private final Semaphore semaphore = new Semaphore(1);

    /**
     * Tracks whether an immediate retry has already been fired for the current failure episode. Set
     * by {@link #handleOutcome(SyncOutcome)} on a fresh {@link SyncOutcome#FAILURE}; cleared on
     * {@link SyncOutcome#SUCCESS} or once the retry's own outcome has been evaluated. Guarantees at
     * most one immediate retry per failure episode.
     */
    private final AtomicBoolean retryPending = new AtomicBoolean(false);

    /**
     * Set by {@link #triggerOnRegistration()} until a pass starts on this node; every pass clears it
     * as it starts. A pass that starts after the registration looks the plan up with the new token,
     * while one that was already running may have looked it up before.
     */
    private final AtomicBoolean registrationPassPending = new AtomicBoolean(false);

    private final Client client;
    private final ThreadPool threadPool;
    private final List<AbstractConsumerService> synchronizers;
    private final SetupReadiness setupReadiness;
    private final ResourceLockService resourceLockService;

    /**
     * Constructs a new CatalogSyncJob.
     *
     * @param client The OpenSearch client used for administrative index operations.
     * @param consumersIndex The wrapper for accessing and managing the internal Consumers index.
     * @param environment The OpenSearch environment settings, used for path resolution.
     * @param threadPool The thread pool manager, used to offload blocking tasks to the generic
     *     executor.
     * @param engineService The engine service for notifying the Engine about IOC updates.
     * @param spaceService The shared space service.
     * @param securityAnalyticsService The shared SAP service.
     * @param userOverridesService The shared user overrides registry, re-applied after every sync.
     * @param resourceLockService The lock service holding the cluster-wide sync lock.
     */
    public CatalogSyncJob(
            Client client,
            ConsumersIndex consumersIndex,
            Environment environment,
            ThreadPool threadPool,
            EngineService engineService,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            UserOverridesService userOverridesService,
            ResourceLockService resourceLockService) {
        this.client = client;
        this.setupReadiness = new SetupReadiness(client);
        this.threadPool = threadPool;
        this.resourceLockService = resourceLockService;
        this.synchronizers =
                List.of(
                        new ConsumerRulesetService(
                                client,
                                consumersIndex,
                                environment,
                                spaceService,
                                securityAnalyticsService,
                                userOverridesService),
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
        // The job document is reconciled with the settings on start and on every dynamic change,
        // but a stale `enabled: true` document (written by an older version, restored from a
        // snapshot, or edited by hand) must never reach CTI while the setting says otherwise.
        if (!PluginSettings.getInstance().isUpdateOnSchedule()) {
            log.info(Constants.I_LOG_CATALOG_SYNC_SKIPPED_DISABLED, context.getJobId());
            return;
        }
        String jobId = context.getJobId();
        this.start(
                ActionListener.wrap(
                        started -> {
                            if (started) {
                                log.debug("Executing Consumer Sync Job (ID: {})", jobId);
                            } else {
                                log.warn(
                                        "CatalogSyncJob (ID: {}) skipped because synchronization is already"
                                                + " running.",
                                        jobId);
                            }
                        },
                        e ->
                                log.error(
                                        "CatalogSyncJob (ID: {}) could not start: {}", jobId, e.getMessage(), e)));
    }

    /**
     * Checks if a synchronization pass is currently running on this node. Passes running on other
     * nodes are not visible here; {@link #trigger(ActionListener)} reports those.
     *
     * @return true if running, false otherwise.
     */
    public boolean isRunning() {
        return this.semaphore.availablePermits() == 0;
    }

    /** Attempts to trigger the synchronization process manually. */
    public void trigger() {
        this.trigger(
                ActionListener.wrap(
                        started -> {
                            if (!started) {
                                log.warn(
                                        "Attempted to trigger CatalogSyncJob manually while it is already running.");
                            }
                        },
                        e -> log.error("CatalogSyncJob could not start: {}", e.getMessage(), e)));
    }

    /**
     * Triggers the startup sync. A held cluster lock at startup may be one this node left behind: a
     * crash or a restart in the middle of a pass skips the release, and the lock only goes stale once
     * {@link PluginSettings#RESOURCE_LOCK_STALE_THRESHOLD_MILLIS} has passed since its last renewal.
     * Instead of leaving the content to the next scheduled run, one interval away, the startup sync
     * is retried once, when such a lock would have gone stale. The retry takes the lock like any
     * other pass, so it never runs alongside another one; if the lock is still held, because another
     * node really is syncing, it is skipped and no further retry is scheduled.
     *
     * <p>The same single retry covers a lock that could not be requested at all, for instance because
     * the primary of the lock index is not assigned yet after a restart. Before the cluster lock, the
     * startup sync did not depend on that index.
     */
    public void triggerOnStartup() {
        this.trigger(
                ActionListener.wrap(
                        started -> {
                            if (!started) {
                                this.scheduleStartupRetry("Catalog sync lock is held at startup");
                            }
                        },
                        e -> {
                            log.error("CatalogSyncJob could not start: {}", e.getMessage(), e);
                            this.scheduleStartupRetry("Catalog sync lock could not be requested at startup");
                        }));
    }

    /**
     * Schedules the one startup retry for when a lock this node left behind would have gone stale.
     *
     * @param reason Why the startup sync did not start, for the log.
     */
    private void scheduleStartupRetry(String reason) {
        long delay =
                PluginSettings.getInstance().getResourceLockStaleThresholdMillis()
                        + STARTUP_RETRY_MARGIN_MILLIS;
        log.info("{}; retrying the startup sync once in {} ms.", reason, delay);
        this.threadPool.schedule(
                () -> this.trigger(), TimeValue.timeValueMillis(delay), ThreadPool.Names.GENERIC);
    }

    /**
     * Starts a pass after an access token was registered, so the content of the environment's plan is
     * downloaded, or swapped in, without waiting for the next scheduled run. The pass looks the plan
     * up with the new token and moves each consumer to the data source the plan provides, like any
     * other pass.
     *
     * <p>Must be called on the node that stored the token: the token only reaches the memory of that
     * node, and the pass runs on the node that starts it.
     *
     * <p>A pass that is already running, on this node or on another one, may have looked the plan up
     * before the token was stored. The request then waits, and is retried every {@value
     * #REGISTRATION_RETRY_DELAY_MILLIS} ms until a pass starts on this node. A pass started meanwhile
     * by anything else on this node covers it as well.
     *
     * <p>Skipped when {@link PluginSettings#UPDATE_ON_SCHEDULE} is false: with automatic updates off,
     * the plan's content is applied by the next on-demand update.
     */
    public void triggerOnRegistration() {
        if (!PluginSettings.getInstance().isUpdateOnSchedule()) {
            log.info(Constants.I_LOG_REGISTRATION_UPDATE_SKIPPED_DISABLED);
            return;
        }
        // A request that is already waiting starts a pass that reads the latest token, so it covers
        // this registration too.
        if (this.registrationPassPending.getAndSet(true)) {
            return;
        }
        this.startRegistrationPass(true);
    }

    /**
     * Starts the pass requested by {@link #triggerOnRegistration()}, or schedules another attempt if
     * a pass is running.
     *
     * @param firstAttempt whether this is the first attempt, to log the wait only once.
     */
    private void startRegistrationPass(boolean firstAttempt) {
        if (!this.registrationPassPending.get()) {
            // A pass started since the registration, so it applied the plan.
            return;
        }
        this.trigger(
                ActionListener.wrap(
                        started -> {
                            if (started) {
                                log.info(Constants.I_LOG_REGISTRATION_UPDATE_STARTED);
                                return;
                            }
                            if (firstAttempt) {
                                log.info(Constants.I_LOG_REGISTRATION_UPDATE_WAITING);
                            }
                            try {
                                this.threadPool.schedule(
                                        () -> this.startRegistrationPass(false),
                                        TimeValue.timeValueMillis(REGISTRATION_RETRY_DELAY_MILLIS),
                                        ThreadPool.Names.GENERIC);
                            } catch (Exception e) {
                                // Left set, the flag would turn every later registration into a no-op.
                                this.registrationPassPending.set(false);
                                log.error(Constants.E_LOG_REGISTRATION_UPDATE_FAILED, e.getMessage(), e);
                            }
                        },
                        e -> {
                            this.registrationPassPending.set(false);
                            log.error(Constants.E_LOG_REGISTRATION_UPDATE_FAILED, e.getMessage(), e);
                        }));
    }

    /**
     * Reports whether a registration is still waiting for its pass to start. Exposed for tests.
     *
     * @return true if a registration is waiting for its pass.
     */
    boolean isRegistrationPassPending() {
        return this.registrationPassPending.get();
    }

    /**
     * Attempts to trigger the synchronization process manually, reporting whether a pass started.
     *
     * @param listener Notified with {@code true} if a pass started, {@code false} if one is already
     *     running on this or any other node, or a failure if the cluster lock could not be requested.
     */
    public void trigger(ActionListener<Boolean> listener) {
        this.start(listener);
    }

    /**
     * Starts a pass if none is running anywhere in the cluster: first this node's {@link #semaphore},
     * then the cluster-wide {@link #CLUSTER_LOCK_ID} lock. Shared by {@link
     * #execute(JobExecutionContext)} and {@link #trigger(ActionListener)}.
     *
     * @param listener Notified with whether a pass started.
     */
    private void start(ActionListener<Boolean> listener) {
        if (!this.semaphore.tryAcquire()) {
            CatalogSyncJob.notifyCaller(listener, false);
            return;
        }
        // notifyOnce: the lock service answers through ActionListener.wrap, which turns an exception
        // thrown while handling a response into a call to onFailure. Without the guard, that second
        // call would release the semaphore again and leave it with two permits.
        ActionListener<Boolean> onLock =
                ActionListener.notifyOnce(
                        new ActionListener<>() {
                            @Override
                            public void onResponse(Boolean acquired) {
                                if (!acquired) {
                                    CatalogSyncJob.this.semaphore.release();
                                    CatalogSyncJob.notifyCaller(listener, false);
                                    return;
                                }
                                try {
                                    CatalogSyncJob.this
                                            .threadPool
                                            .generic()
                                            .execute(CatalogSyncJob.this::runSynchronizationPass);
                                } catch (Exception e) {
                                    CatalogSyncJob.this.releaseClusterLock(CatalogSyncJob.this.semaphore::release);
                                    CatalogSyncJob.notifyCallerOfFailure(listener, e);
                                    return;
                                }
                                CatalogSyncJob.notifyCaller(listener, true);
                            }

                            @Override
                            public void onFailure(Exception e) {
                                CatalogSyncJob.this.semaphore.release();
                                CatalogSyncJob.notifyCallerOfFailure(listener, e);
                            }
                        });
        try {
            this.resourceLockService.tryAcquireOnce(CLUSTER_LOCK_ID, onLock);
        } catch (Exception e) {
            onLock.onFailure(e);
        }
    }

    /**
     * Tells the caller whether a pass started. An exception from the caller's listener must not reach
     * the lock callbacks, whose failure path releases the semaphore.
     */
    private static void notifyCaller(ActionListener<Boolean> listener, boolean started) {
        try {
            listener.onResponse(started);
        } catch (Exception e) {
            log.warn("CatalogSyncJob start listener failed: {}", e.getMessage(), e);
        }
    }

    /** Tells the caller that a pass could not start, with the same guard as {@link #notifyCaller}. */
    private static void notifyCallerOfFailure(ActionListener<Boolean> listener, Exception failure) {
        try {
            listener.onFailure(failure);
        } catch (Exception e) {
            log.warn("CatalogSyncJob start listener failed: {}", e.getMessage(), e);
        }
    }

    /**
     * Runs one synchronization pass, renewing the cluster lock while it runs, and, once the lock and
     * then the semaphore have been released, hands the outcome to {@link #handleOutcome(SyncOutcome)}
     * so a failed pass can immediately trigger a single retry.
     */
    private void runSynchronizationPass() {
        // This pass looks the plan up after it starts, so it applies any registration made before.
        this.registrationPassPending.set(false);
        Scheduler.Cancellable renewal = null;
        SyncOutcome outcome = SyncOutcome.SETUP_NOT_READY;
        try {
            renewal = this.scheduleLockRenewal();
            outcome = this.performSynchronization();
        } catch (Exception e) {
            log.error("Error running CatalogSyncJob: {}", e.getMessage(), e);
        } finally {
            if (renewal != null) {
                renewal.cancel();
            }
        }
        SyncOutcome finalOutcome = outcome;
        // The retry must wait for both releases: a retry that raced the lock delete would find the
        // lock document still there, and one that ran before the semaphore release would find the
        // permit unavailable. Either way it would silently no-op.
        this.releaseClusterLock(
                () -> {
                    this.semaphore.release();
                    try {
                        this.handleOutcome(finalOutcome);
                    } catch (Exception e) {
                        log.error("Error handling CatalogSyncJob outcome: {}", e.getMessage(), e);
                    }
                });
    }

    /**
     * Releases the cluster lock and then runs {@code then} exactly once: when the delete completes,
     * or straight away if the release cannot even be sent, so the semaphore is never left held.
     *
     * @param then Run once the lock is released.
     */
    private void releaseClusterLock(Runnable then) {
        AtomicBoolean ran = new AtomicBoolean(false);
        Runnable once =
                () -> {
                    if (ran.compareAndSet(false, true)) {
                        then.run();
                    }
                };
        try {
            this.resourceLockService.release(CLUSTER_LOCK_ID, once);
        } catch (Exception e) {
            log.error("Failed to release the catalog sync lock: {}", e.getMessage(), e);
            once.run();
        }
    }

    /**
     * Keeps the cluster lock from going stale while a pass runs, renewing it three times per stale
     * threshold. If this node dies, the renewals stop and another node can take the lock over.
     *
     * @return the renewal task, to cancel when the pass ends.
     */
    private Scheduler.Cancellable scheduleLockRenewal() {
        long interval =
                Math.max(1000L, PluginSettings.getInstance().getResourceLockStaleThresholdMillis() / 3);
        return this.threadPool.scheduleWithFixedDelay(
                () -> this.resourceLockService.renew(CLUSTER_LOCK_ID),
                TimeValue.timeValueMillis(interval),
                ThreadPool.Names.GENERIC);
    }

    /**
     * Reacts to the outcome of a synchronization pass. A fresh failure triggers exactly one immediate
     * retry via {@link #trigger(ActionListener)}; the retry's own outcome is evaluated the same way
     * but the {@link #retryPending} flag prevents it from triggering a second retry, so a
     * persistently failing sync falls back to waiting for the next scheduled run. A retry that does
     * not start clears the flag itself, since no outcome will come back to clear it.
     *
     * @param outcome The result of the synchronization pass that just completed.
     */
    void handleOutcome(SyncOutcome outcome) {
        switch (outcome) {
            case SUCCESS -> this.retryPending.set(false);
            case FAILURE -> {
                if (this.retryPending.compareAndSet(false, true)) {
                    log.warn("Synchronization failed; triggering one immediate retry.");
                    // Left set, the flag would make the next unrelated failure of this node, maybe hours
                    // later, look like this retry's own outcome, and it would get no retry.
                    this.trigger(
                            ActionListener.wrap(
                                    started -> {
                                        if (!started) {
                                            log.warn(
                                                    "Immediate retry not started: a synchronization is already"
                                                            + " running.");
                                            this.retryPending.set(false);
                                        }
                                    },
                                    e -> {
                                        log.error("Immediate retry could not start: {}", e.getMessage(), e);
                                        this.retryPending.set(false);
                                    }));
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
            // Content download requires two things to be true: the Setup plugin reported ready, and
            // the target indices it provisions exist. This is the first; the second is checked per
            // consumer by AbstractConsumerService, which skips its own pass when any of its indices
            // is absent, so one mis-provisioned index cannot silently become a squatted one.
            if (!this.waitForSetup()) {
                log.error(
                        "Setup plugin initialization did not complete in time. Skipping catalog"
                                + " synchronization; it will be retried on the next scheduled run.");
                return SyncOutcome.SETUP_NOT_READY;
            }
            boolean anyFailure = false;
            for (AbstractConsumerService synchronizer : this.synchronizers) {
                try {
                    // true means the pass did not fully complete for a transient reason — the
                    // configured CTI feed was unreachable (fell back to the local snapshot), the Setup
                    // plugin had not yet provisioned this consumer's target indices, or the consumer
                    // finished with a phase still pending and asked for a retry itself — and should be
                    // retried immediately rather than waiting for the next scheduled run.
                    boolean needsRetry = synchronizer.synchronize();
                    if (needsRetry) {
                        anyFailure = true;
                        log.warn(
                                "{} did not fully synchronize this pass (unreachable feed, indices not yet"
                                        + " provisioned, or a phase left pending); retrying.",
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
