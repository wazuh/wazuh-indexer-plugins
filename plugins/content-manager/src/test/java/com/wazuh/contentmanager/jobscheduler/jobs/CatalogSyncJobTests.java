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

import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.ResourceLockService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link CatalogSyncJob} class. This test suite validates the scheduled job
 * responsible for synchronizing the CTI catalog with local indices.
 *
 * <p>Tests verify job state management, job type identification, and execution lifecycle. The
 * catalog sync job is a critical component that ensures local content indices remain synchronized
 * with the remote CTI catalog by periodically fetching and applying updates.
 */
public class CatalogSyncJobTests extends OpenSearchTestCase {

    private CatalogSyncJob catalogSyncJob;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;
    @Mock private ThreadPool threadPool;
    @Mock private EngineService engineService;
    @Mock private SpaceService spaceService;
    @Mock private SecurityAnalyticsService securityAnalyticsService;
    @Mock private GetRequestBuilder getRequestBuilder;
    @Mock private GetResponse getResponse;
    @Mock private ResourceLockService resourceLockService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        when(this.threadPool.getThreadContext()).thenReturn(threadContext);

        // By default no other node holds the cluster lock, and releasing it completes at once.
        this.stubClusterLock(true);
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(1)).run();
                            return null;
                        })
                .when(this.resourceLockService)
                .release(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(Runnable.class));

        this.catalogSyncJob =
                new CatalogSyncJob(
                        this.client,
                        this.consumersIndex,
                        this.environment,
                        this.threadPool,
                        this.engineService,
                        this.spaceService,
                        this.securityAnalyticsService,
                        mock(UserOverridesService.class),
                        this.resourceLockService);

        when(this.client.prepareGet(Constants.INDEX_SETUP_STATUS, Constants.SETUP_STATUS_DOC_ID))
                .thenReturn(this.getRequestBuilder);
        when(this.getRequestBuilder.get()).thenReturn(this.getResponse);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Test that the {@link CatalogSyncJob#isRunning()} method returns false initially. */
    public void testIsRunningReturnsFalseInitially() {
        boolean isRunning = this.catalogSyncJob.isRunning();

        Assert.assertFalse(isRunning);
    }

    /** Test that the {@link CatalogSyncJob#JOB_TYPE} constant is correctly defined. */
    public void testJobTypeConstant() {
        Assert.assertEquals("consumer-sync-task", CatalogSyncJob.JOB_TYPE);
    }

    /** The setup status marker must be read from the dedicated .wazuh-setup-status index. */
    public void testSetupStatusIndexConstant() {
        Assert.assertEquals(".wazuh-setup-status", Constants.INDEX_SETUP_STATUS);
    }

    /** Setup marker already ready -> waitForSetup returns true on the first check. */
    public void testWaitForSetup_markerReady_returnsTrue() {
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsMap())
                .thenReturn(Map.of(Constants.KEY_STATUS, Constants.SETUP_STATUS_READY));

        Assert.assertTrue(this.catalogSyncJob.waitForSetup());
    }

    /** Setup marker reports failed -> waitForSetup returns false immediately, with no retries. */
    public void testWaitForSetup_markerFailed_returnsFalseImmediately() {
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsMap())
                .thenReturn(Map.of(Constants.KEY_STATUS, Constants.SETUP_STATUS_FAILED));

        long start = System.nanoTime();
        boolean result = this.catalogSyncJob.waitForSetup();
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        Assert.assertFalse(result);
        Assert.assertTrue(
                "waitForSetup() must not sleep through the backoff when the marker already says"
                        + " failed",
                elapsedMillis < 1000);
    }

    /** When setup never completes, the synchronization pass is skipped entirely. */
    public void testTrigger_setupIncomplete_skipsSynchronization() {
        ExecutorService sameThreadExecutor = mock(ExecutorService.class);
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(sameThreadExecutor)
                .execute(any(Runnable.class));
        when(this.threadPool.generic()).thenReturn(sameThreadExecutor);

        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(false).when(job).waitForSetup();

        job.trigger();

        verifyNoInteractions(this.consumersIndex);
        Assert.assertFalse("Semaphore must be released after a skipped pass", job.isRunning());
        Assert.assertFalse(
                "A skipped pass (Setup not ready) must not arm the retry flag", job.isRetryPending());
        verify(job, times(1)).trigger();
    }

    /**
     * A second {@code trigger()} call made while a pass is still in flight (semaphore held, task not
     * yet completed) must be rejected without starting a second pass. Uses a plain unstubbed executor
     * mock, so the first submitted task is captured but never actually run -- simulating a pass that
     * is genuinely still in progress.
     */
    public void testTrigger_whileAlreadyRunning_isRejectedAndDoesNotStartSecondPass() {
        ExecutorService neverRunsExecutor = mock(ExecutorService.class);
        when(this.threadPool.generic()).thenReturn(neverRunsExecutor);

        this.catalogSyncJob.trigger();
        Assert.assertTrue(
                "First trigger() must acquire the semaphore and remain running until its task"
                        + " completes",
                this.catalogSyncJob.isRunning());

        this.catalogSyncJob.trigger();

        verify(neverRunsExecutor, times(1)).execute(any(Runnable.class));
        Assert.assertTrue(
                "Semaphore must remain held; the second trigger() must not release or re-acquire it",
                this.catalogSyncJob.isRunning());
    }

    /**
     * A scheduled {@code execute()} call that lands while a pass is still in flight must be rejected
     * the same way {@code trigger()} is, without starting a second pass.
     */
    public void testExecute_whileAlreadyRunning_isRejectedAndDoesNotStartSecondPass() {
        ExecutorService neverRunsExecutor = mock(ExecutorService.class);
        when(this.threadPool.generic()).thenReturn(neverRunsExecutor);

        this.catalogSyncJob.trigger();
        Assert.assertTrue(this.catalogSyncJob.isRunning());

        JobExecutionContext context = mock(JobExecutionContext.class);
        this.catalogSyncJob.execute(context);

        verify(neverRunsExecutor, times(1)).execute(any(Runnable.class));
        Assert.assertTrue(
                "A concurrent scheduled execute() must not start a second pass while one is in" + " flight",
                this.catalogSyncJob.isRunning());
    }

    /** Makes the cluster lock report {@code acquired} to every request. */
    @SuppressWarnings("unchecked")
    private void stubClusterLock(boolean acquired) {
        doAnswer(
                        invocation -> {
                            ((ActionListener<Boolean>) invocation.getArgument(1)).onResponse(acquired);
                            return null;
                        })
                .when(this.resourceLockService)
                .tryAcquireOnce(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(ActionListener.class));
    }

    /**
     * A pass already running on another node holds the cluster lock, so {@code trigger()} on this
     * node must not start a second one, and must say so. This is the case the per-node semaphore
     * alone could not see.
     */
    public void testTrigger_clusterLockHeldByAnotherNode_doesNotStartPass() {
        this.useSameThreadExecutor();
        this.stubClusterLock(false);
        CatalogSyncJob job = spy(this.catalogSyncJob);
        PlainActionFuture<Boolean> started = new PlainActionFuture<>();

        job.trigger(started);

        Assert.assertFalse(started.actionGet());
        verify(job, never()).performSynchronization();
        verify(this.resourceLockService, never()).release(anyString(), any(Runnable.class));
        Assert.assertFalse("The semaphore must be released when the lock is held", job.isRunning());
    }

    /** A scheduled run landing while another node holds the cluster lock is skipped. */
    public void testExecute_clusterLockHeldByAnotherNode_skipsPass() {
        this.useSameThreadExecutor();
        this.stubClusterLock(false);
        CatalogSyncJob job = spy(this.catalogSyncJob);

        job.execute(mock(JobExecutionContext.class));

        verify(job, never()).performSynchronization();
        Assert.assertFalse(job.isRunning());
    }

    /** A pass that ran releases the cluster lock, and then the semaphore. */
    public void testTrigger_passCompletes_releasesClusterLock() {
        this.useSameThreadExecutor();
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();
        PlainActionFuture<Boolean> started = new PlainActionFuture<>();

        job.trigger(started);

        Assert.assertTrue(started.actionGet());
        verify(job, times(1)).performSynchronization();
        verify(this.resourceLockService, times(1))
                .release(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(Runnable.class));
        Assert.assertFalse(job.isRunning());
    }

    /** If the lock index cannot be reached, no pass starts and the semaphore is not left held. */
    @SuppressWarnings("unchecked")
    public void testTrigger_clusterLockFails_reportsFailureAndReleasesSemaphore() {
        this.useSameThreadExecutor();
        doAnswer(
                        invocation -> {
                            ((ActionListener<Boolean>) invocation.getArgument(1))
                                    .onFailure(new RuntimeException("lock index unavailable"));
                            return null;
                        })
                .when(this.resourceLockService)
                .tryAcquireOnce(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(ActionListener.class));
        CatalogSyncJob job = spy(this.catalogSyncJob);
        PlainActionFuture<Boolean> started = new PlainActionFuture<>();

        job.trigger(started);

        expectThrows(Exception.class, started::actionGet);
        verify(job, never()).performSynchronization();
        Assert.assertFalse(job.isRunning());
    }

    /**
     * The lock is renewed while a pass runs and the renewal stops when it ends, so a long pass keeps
     * the lock and a finished one does not keep it alive.
     */
    public void testTrigger_passRenewsClusterLockAndCancelsRenewalWhenDone() {
        this.useSameThreadExecutor();
        Scheduler.Cancellable renewal = mock(Scheduler.Cancellable.class);
        when(this.threadPool.scheduleWithFixedDelay(
                        any(Runnable.class), any(TimeValue.class), eq(ThreadPool.Names.GENERIC)))
                .thenAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return renewal;
                        });
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();

        job.trigger();

        verify(this.resourceLockService, times(1)).renew(CatalogSyncJob.CLUSTER_LOCK_ID);
        verify(renewal, times(1)).cancel();
    }

    /**
     * The immediate retry of a failed pass must wait for the cluster lock to be released. Fired
     * earlier, it would find the lock document still there and be skipped as already running.
     */
    public void testRetry_waitsForClusterLockRelease() {
        this.useSameThreadExecutor();
        AtomicReference<Runnable> pendingRelease = new AtomicReference<>();
        doAnswer(
                        invocation -> {
                            pendingRelease.set(invocation.getArgument(1));
                            return null;
                        })
                .when(this.resourceLockService)
                .release(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(Runnable.class));
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.FAILURE, CatalogSyncJob.SyncOutcome.SUCCESS)
                .when(job)
                .performSynchronization();

        job.trigger();

        verify(job, times(1)).performSynchronization();
        Assert.assertTrue("The semaphore is held until the lock is released", job.isRunning());

        pendingRelease.get().run();

        verify(job, times(2)).performSynchronization();
    }

    /** Captures the task handed to {@code threadPool.schedule()} and the delay it was given. */
    private AtomicReference<Runnable> captureScheduled(AtomicReference<TimeValue> delay) {
        AtomicReference<Runnable> scheduled = new AtomicReference<>();
        when(this.threadPool.schedule(any(Runnable.class), any(TimeValue.class), anyString()))
                .thenAnswer(
                        invocation -> {
                            scheduled.set(invocation.getArgument(0));
                            delay.set(invocation.getArgument(1));
                            return null;
                        });
        return scheduled;
    }

    /** A startup sync that gets the lock runs at once and schedules no retry. */
    public void testTriggerOnStartup_lockFree_runsWithoutRetry() {
        this.useSameThreadExecutor();
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();

        job.triggerOnStartup();

        verify(job, times(1)).performSynchronization();
        verify(this.threadPool, never())
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
    }

    /**
     * A startup sync that finds the lock held, for instance one this node left behind when restarted
     * in the middle of a pass, retries once when that lock would have gone stale, and runs then.
     */
    public void testTriggerOnStartup_lockHeld_retriesOnceWhenStale() {
        this.useSameThreadExecutor();
        this.stubClusterLock(false);
        AtomicReference<TimeValue> delay = new AtomicReference<>();
        AtomicReference<Runnable> retry = this.captureScheduled(delay);
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();

        job.triggerOnStartup();

        verify(job, never()).performSynchronization();
        Assert.assertNotNull("A retry must be scheduled", retry.get());
        Assert.assertEquals(
                PluginSettings.getInstance().getResourceLockStaleThresholdMillis()
                        + CatalogSyncJob.STARTUP_RETRY_MARGIN_MILLIS,
                delay.get().millis());

        this.stubClusterLock(true);
        retry.get().run();

        verify(job, times(1)).performSynchronization();
    }

    /**
     * If the lock is still held when the retry runs, another node really is syncing: the retry is
     * skipped and no second retry is scheduled.
     */
    public void testTriggerOnStartup_lockStillHeldOnRetry_doesNotRetryAgain() {
        this.useSameThreadExecutor();
        this.stubClusterLock(false);
        AtomicReference<Runnable> retry = this.captureScheduled(new AtomicReference<>());
        CatalogSyncJob job = spy(this.catalogSyncJob);

        job.triggerOnStartup();
        retry.get().run();

        verify(job, never()).performSynchronization();
        verify(this.threadPool, times(1))
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
    }

    /** Makes every request for the cluster lock fail, as when the lock index cannot be reached. */
    @SuppressWarnings("unchecked")
    private void failClusterLock() {
        doAnswer(
                        invocation -> {
                            ((ActionListener<Boolean>) invocation.getArgument(1))
                                    .onFailure(new RuntimeException("lock index unavailable"));
                            return null;
                        })
                .when(this.resourceLockService)
                .tryAcquireOnce(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(ActionListener.class));
    }

    /**
     * If the renewal cannot even be scheduled, the pass does not run without it, and the lock and the
     * semaphore are still released.
     */
    public void testPass_renewalCannotBeScheduled_releasesLockAndSemaphore() {
        this.useSameThreadExecutor();
        when(this.threadPool.scheduleWithFixedDelay(
                        any(Runnable.class), any(TimeValue.class), anyString()))
                .thenThrow(new RejectedExecutionException("shutting down"));
        CatalogSyncJob job = spy(this.catalogSyncJob);

        job.trigger();

        verify(job, never()).performSynchronization();
        verify(this.resourceLockService, times(1))
                .release(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(Runnable.class));
        Assert.assertFalse(job.isRunning());
    }

    /**
     * A release that cannot even be sent still frees the semaphore; otherwise this node would answer
     * 409 to every update until restarted.
     */
    public void testPass_releaseThrowing_stillReleasesTheSemaphore() {
        this.useSameThreadExecutor();
        doThrow(new IllegalStateException("node closed"))
                .when(this.resourceLockService)
                .release(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(Runnable.class));
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();

        job.trigger();

        Assert.assertFalse(job.isRunning());
    }

    /** If the pass cannot be handed to the executor, the lock and the semaphore are released. */
    public void testTrigger_executorRejects_releasesLockAndSemaphore() {
        ExecutorService rejecting = mock(ExecutorService.class);
        doThrow(new RejectedExecutionException("shutting down"))
                .when(rejecting)
                .execute(any(Runnable.class));
        when(this.threadPool.generic()).thenReturn(rejecting);
        PlainActionFuture<Boolean> started = new PlainActionFuture<>();

        this.catalogSyncJob.trigger(started);

        expectThrows(Exception.class, started::actionGet);
        verify(this.resourceLockService, times(1))
                .release(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(Runnable.class));
        Assert.assertFalse(this.catalogSyncJob.isRunning());
    }

    /**
     * A caller whose listener throws must not make the lock service's failure path release the
     * semaphore a second time. With two permits, two passes could run on this node at once.
     */
    @SuppressWarnings("unchecked")
    public void testTrigger_throwingCallerListener_doesNotReleaseTheSemaphoreTwice() {
        // Answers the way ActionListener.wrap does: an exception thrown by onResponse goes to
        // onFailure.
        doAnswer(
                        invocation -> {
                            ActionListener<Boolean> l = invocation.getArgument(1);
                            try {
                                l.onResponse(false);
                            } catch (Exception e) {
                                l.onFailure(e);
                            }
                            return null;
                        })
                .when(this.resourceLockService)
                .tryAcquireOnce(eq(CatalogSyncJob.CLUSTER_LOCK_ID), any(ActionListener.class));
        this.catalogSyncJob.trigger(
                new ActionListener<>() {
                    @Override
                    public void onResponse(Boolean started) {
                        throw new IllegalStateException("caller failed");
                    }

                    @Override
                    public void onFailure(Exception e) {}
                });

        ExecutorService neverRunsExecutor = mock(ExecutorService.class);
        when(this.threadPool.generic()).thenReturn(neverRunsExecutor);
        this.stubClusterLock(true);
        this.catalogSyncJob.trigger();
        this.catalogSyncJob.trigger();

        verify(neverRunsExecutor, times(1)).execute(any(Runnable.class));
    }

    /**
     * An immediate retry that does not start, because another node holds the lock, clears the retry
     * flag itself. No outcome will come back to clear it, and left set it would cost the next
     * unrelated failure its own retry.
     */
    public void testHandleOutcome_retryNotStarted_clearsTheRetryFlag() {
        this.useSameThreadExecutor();
        this.stubClusterLock(false);
        CatalogSyncJob job = spy(this.catalogSyncJob);

        job.handleOutcome(CatalogSyncJob.SyncOutcome.FAILURE);

        verify(job, never()).performSynchronization();
        Assert.assertFalse(job.isRetryPending());
    }

    /** The same holds when the lock cannot even be requested. */
    public void testHandleOutcome_retryCannotRequestTheLock_clearsTheRetryFlag() {
        this.useSameThreadExecutor();
        this.failClusterLock();
        CatalogSyncJob job = spy(this.catalogSyncJob);

        job.handleOutcome(CatalogSyncJob.SyncOutcome.FAILURE);

        verify(job, never()).performSynchronization();
        Assert.assertFalse(job.isRetryPending());
    }

    /**
     * A startup sync that cannot even request the lock, for instance because the primary of the lock
     * index is not assigned yet after a restart, gets the same single retry.
     */
    public void testTriggerOnStartup_lockRequestFails_retriesOnce() {
        this.useSameThreadExecutor();
        this.failClusterLock();
        AtomicReference<TimeValue> delay = new AtomicReference<>();
        AtomicReference<Runnable> retry = this.captureScheduled(delay);
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();

        job.triggerOnStartup();

        verify(job, never()).performSynchronization();
        Assert.assertNotNull("A retry must be scheduled", retry.get());
        Assert.assertEquals(
                PluginSettings.getInstance().getResourceLockStaleThresholdMillis()
                        + CatalogSyncJob.STARTUP_RETRY_MARGIN_MILLIS,
                delay.get().millis());

        this.stubClusterLock(true);
        retry.get().run();

        verify(job, times(1)).performSynchronization();
    }

    /** Makes {@code threadPool.generic()} run submitted tasks synchronously on the calling thread. */
    private void useSameThreadExecutor() {
        ExecutorService sameThreadExecutor = mock(ExecutorService.class);
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(sameThreadExecutor)
                .execute(any(Runnable.class));
        when(this.threadPool.generic()).thenReturn(sameThreadExecutor);
    }

    /** A fresh failure fires exactly one immediate retry; a retry that succeeds clears the flag. */
    public void testHandleOutcome_failure_triggersOneImmediateRetry() {
        this.useSameThreadExecutor();
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();

        job.handleOutcome(CatalogSyncJob.SyncOutcome.FAILURE);

        verify(job, times(1)).trigger(any(ActionListener.class));
        verify(job, times(1)).performSynchronization();
        Assert.assertFalse("Flag must be clear after the retry succeeds", job.isRetryPending());
        Assert.assertFalse("Semaphore must be released after the retry completes", job.isRunning());
    }

    /** If the one immediate retry also fails, no second retry is triggered. */
    public void testHandleOutcome_retryAlsoFails_doesNotRetryAgain() {
        this.useSameThreadExecutor();
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.FAILURE).when(job).performSynchronization();

        job.handleOutcome(CatalogSyncJob.SyncOutcome.FAILURE);

        verify(job, times(1)).trigger(any(ActionListener.class));
        verify(job, times(1)).performSynchronization();
        Assert.assertFalse(
                "Flag must be reset so the next distinct failure episode gets its own retry",
                job.isRetryPending());
        Assert.assertFalse("Semaphore must be released after the retry completes", job.isRunning());
    }

    /** A successful pass never triggers a retry and leaves the retry flag clear. */
    public void testHandleOutcome_success_leavesRetryFlagClear() {
        CatalogSyncJob job = spy(this.catalogSyncJob);

        job.handleOutcome(CatalogSyncJob.SyncOutcome.SUCCESS);

        verify(job, never()).trigger(any(ActionListener.class));
        Assert.assertFalse(job.isRetryPending());
    }

    /**
     * Regression test: if the immediate retry's own outcome is {@code SETUP_NOT_READY} (rather than
     * {@code SUCCESS} or {@code FAILURE}), {@code retryPending} must still be cleared. Otherwise a
     * later, unrelated failure would be misread as that stale retry's outcome and would not get its
     * own immediate retry.
     */
    public void testHandleOutcome_retryHitsSetupNotReady_clearsFlagSoNextFailureRetries() {
        this.useSameThreadExecutor();
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SETUP_NOT_READY, CatalogSyncJob.SyncOutcome.SUCCESS)
                .when(job)
                .performSynchronization();

        job.handleOutcome(CatalogSyncJob.SyncOutcome.FAILURE);

        Assert.assertFalse(
                "Flag must be cleared even though the retry's own outcome was SETUP_NOT_READY, not"
                        + " SUCCESS/FAILURE",
                job.isRetryPending());

        job.handleOutcome(CatalogSyncJob.SyncOutcome.FAILURE);

        verify(job, times(2)).trigger(any(ActionListener.class));
        verify(job, times(2)).performSynchronization();
        Assert.assertFalse(
                "The second, unrelated failure must trigger and resolve its own retry",
                job.isRetryPending());
    }

    /** A scheduled run that fails transiently triggers exactly one immediate retry. */
    public void testExecute_transientFailureThenSuccess_triggersOneRetry() {
        this.useSameThreadExecutor();
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.FAILURE, CatalogSyncJob.SyncOutcome.SUCCESS)
                .when(job)
                .performSynchronization();
        JobExecutionContext context = mock(JobExecutionContext.class);

        job.execute(context);

        verify(job, times(1)).trigger(any(ActionListener.class));
        verify(job, times(2)).performSynchronization();
        Assert.assertFalse(job.isRunning());
    }

    /**
     * The semaphore must be released before the retry is triggered, otherwise the nested {@code
     * trigger()} call inside {@code handleOutcome()} would find the permit unavailable and silently
     * no-op, leaving {@code performSynchronization()} invoked only once (the original failing pass)
     * instead of twice (the original pass plus its retry).
     */
    public void testSemaphoreReleasedBeforeRetryTriggered() {
        this.useSameThreadExecutor();
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.FAILURE, CatalogSyncJob.SyncOutcome.SUCCESS)
                .when(job)
                .performSynchronization();

        job.trigger();

        verify(job, times(2)).performSynchronization();
        Assert.assertFalse("Semaphore must end released", job.isRunning());
    }

    /**
     * With {@code update_on_schedule} disabled, a scheduled fire must not synchronize anything, even
     * if the job document that produced it still says {@code enabled: true}. This is the guard that
     * makes an air-gapped deployment safe against a stale document.
     */
    public void testExecute_updateOnScheduleDisabled_doesNotSynchronize() {
        PluginSettings.getInstance().setUpdateOnSchedule(false);
        try {
            this.useSameThreadExecutor();
            CatalogSyncJob job = spy(this.catalogSyncJob);
            JobExecutionContext context = mock(JobExecutionContext.class);

            job.execute(context);

            verify(job, times(0)).performSynchronization();
            verifyNoInteractions(this.consumersIndex);
            Assert.assertFalse(
                    "A skipped scheduled fire must not acquire the semaphore", job.isRunning());
        } finally {
            PluginSettings.getInstance().setUpdateOnSchedule(true);
        }
    }

    /**
     * The guard applies only to the scheduled path. {@code trigger()} backs the on-demand update API,
     * which is gated separately by {@code update_on_demand}, so it must still run.
     */
    public void testTrigger_updateOnScheduleDisabled_stillSynchronizes() {
        PluginSettings.getInstance().setUpdateOnSchedule(false);
        try {
            this.useSameThreadExecutor();
            CatalogSyncJob job = spy(this.catalogSyncJob);
            doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();

            job.trigger();

            verify(job, times(1)).performSynchronization();
            Assert.assertFalse("Semaphore must end released", job.isRunning());
        } finally {
            PluginSettings.getInstance().setUpdateOnSchedule(true);
        }
    }

    /** With the setting enabled, a scheduled fire runs a synchronization pass as before. */
    public void testExecute_updateOnScheduleEnabled_synchronizes() {
        PluginSettings.getInstance().setUpdateOnSchedule(true);
        this.useSameThreadExecutor();
        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(CatalogSyncJob.SyncOutcome.SUCCESS).when(job).performSynchronization();
        JobExecutionContext context = mock(JobExecutionContext.class);

        job.execute(context);

        verify(job, times(1)).performSynchronization();
        Assert.assertFalse("Semaphore must end released", job.isRunning());
    }
}
