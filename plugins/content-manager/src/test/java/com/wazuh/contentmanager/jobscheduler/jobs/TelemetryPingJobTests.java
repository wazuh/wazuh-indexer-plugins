/*
 * Copyright (C) 2026, Wazuh Inc.
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

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.cti.console.client.TelemetryClient;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link TelemetryPingJob} class. This test suite validates the scheduled job
 * responsible for sending a periodic telemetry ping to the Wazuh CTI API.
 *
 * <p>Tests verify job type identification, dynamic enablement/disablement (hot-reload), and the
 * concurrency control mechanisms ensuring tasks do not overlap.
 */
public class TelemetryPingJobTests extends OpenSearchTestCase {

    private TelemetryPingJob telemetryPingJob;
    private AutoCloseable closeable;

    @Mock private ClusterService clusterService;
    @Mock private ClusterState clusterState;
    @Mock private Metadata metadata;
    @Mock private ThreadPool threadPool;
    @Mock private Environment environment;
    @Mock private JobExecutionContext context;
    @Mock private ExecutorService executorService;
    @Mock private TelemetryClient telemetryClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);

        // Initialize PluginSettings with empty settings so we can modify it dynamically
        PluginSettings.getInstance(Settings.EMPTY);

        // Mock
        when(this.threadPool.generic()).thenReturn(this.executorService);
        when(this.clusterService.state()).thenReturn(this.clusterState);
        when(this.clusterState.metadata()).thenReturn(this.metadata);
        when(this.metadata.clusterUUID()).thenReturn("test-cluster-uuid");

        this.telemetryPingJob =
                new TelemetryPingJob(
                        Settings.EMPTY,
                        this.clusterService,
                        this.threadPool,
                        this.environment,
                        this.telemetryClient);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Test that the {@link TelemetryPingJob#JOB_TYPE} constant is correctly defined. */
    public void testJobTypeConstant() {
        Assert.assertEquals("telemetry-ping-task", TelemetryPingJob.JOB_TYPE);
    }

    /**
     * * Test that the job skips execution when telemetry is dynamically disabled via PluginSettings.
     */
    public void testExecute_TelemetryDisabled() {
        // Disable telemetry dynamically
        PluginSettings.getInstance().setTelemetryEnabled(false);

        this.telemetryPingJob.execute(this.context);

        // Verify that the job does not attempt to offload any tasks to the thread pool
        verifyNoInteractions(this.threadPool);
    }

    /**
     * * Test that the job correctly offloads execution to the thread pool when telemetry is enabled.
     */
    public void testExecute_TelemetryEnabled() {
        // Enable job
        PluginSettings.getInstance().setTelemetryEnabled(true);
        when(this.context.getJobId()).thenReturn("test-telemetry-job-id");

        this.telemetryPingJob.execute(this.context);

        // Verify that the job acquires the generic thread pool and submits a runnable
        verify(this.threadPool).generic();
        verify(this.executorService).execute(any(Runnable.class));
    }

    /** Test that the semaphore properly restricts overlapping executions of the job. */
    public void testExecute_ConcurrencyControl() {
        PluginSettings.getInstance().setTelemetryEnabled(true);
        when(this.context.getJobId()).thenReturn("test-telemetry-job-id");

        // 1. First execution: Should acquire the semaphore and submit a runnable
        this.telemetryPingJob.execute(this.context);

        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
        verify(this.executorService, times(1)).execute(runnableCaptor.capture());

        // 2. Second execution: Should be skipped because the previous task's semaphore is still held
        this.telemetryPingJob.execute(this.context);

        // Verify no additional task was submitted to the executor
        verify(this.executorService, times(1)).execute(any(Runnable.class));

        // 3. Simulate the completion of the first task
        Runnable capturedTask = runnableCaptor.getValue();
        capturedTask.run();

        // 4. Third execution: Should succeed in acquiring the semaphore now that it was released
        this.telemetryPingJob.execute(this.context);

        // Verify a second task was successfully submitted to the executor
        verify(this.executorService, times(2)).execute(any(Runnable.class));
    }
}
