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
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.Map;
import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
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
    @Mock private EngineContentLoader engineContentLoader;
    @Mock private GetRequestBuilder getRequestBuilder;
    @Mock private GetResponse getResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);

        this.catalogSyncJob =
                new CatalogSyncJob(
                        this.client,
                        this.consumersIndex,
                        this.environment,
                        this.threadPool,
                        this.engineService,
                        this.engineContentLoader);

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

        verify(job, times(1)).trigger();
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

        verify(job, times(1)).trigger();
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

        verify(job, times(0)).trigger();
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

        verify(job, times(2)).trigger();
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

        verify(job, times(1)).trigger();
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
}
