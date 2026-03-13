/*
 * Copyright (C) 2024-2026, Wazuh Inc.
 */
package com.wazuh.contentmanager.jobscheduler.jobs;

import com.wazuh.contentmanager.cti.console.client.TelemetryClient;
import com.wazuh.contentmanager.jobscheduler.JobExecutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.Version;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.threadpool.ThreadPool;

import java.util.concurrent.Semaphore;

/**
 * Job responsible for sending a periodic telemetry ping to the Wazuh CTI API.
 * This heartbeat includes the environment's unique UUID and the Indexer version.
 */
public class TelemetryPingJob implements JobExecutor {
    private static final Logger log = LogManager.getLogger(TelemetryPingJob.class);

    /** Unique identifier for routing this specific job type within the Job Scheduler. */
    public static final String JOB_TYPE = "telemetry-ping-task";

    /** Configuration setting to enable or disable the telemetry ping. Defaults to true. */
    public static final Setting<Boolean> TELEMETRY_ENABLED = 
        Setting.boolSetting("wazuh.telemetry.enabled", true, Setting.Property.NodeScope);

    /** Semaphore used to ensure only one instance of the job runs at a time. */
    private final Semaphore semaphore = new Semaphore(1);
    
    private final ThreadPool threadPool;
    private final ClusterService clusterService;
    private final TelemetryClient telemetryClient;
    private final boolean isEnabled;

    /**
     * Constructs a new TelemetryPingJob.
     *
     * @param settings The OpenSearch node settings.
     * @param clusterService The service providing access to the cluster state (for UUID retrieval).
     * @param threadPool The thread pool manager used to offload network tasks.
     */
    public TelemetryPingJob(
            Settings settings,
            ClusterService clusterService,
            ThreadPool threadPool) {
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.telemetryClient = new TelemetryClient();
        this.isEnabled = TELEMETRY_ENABLED.get(settings);
    }

    /**
     * Triggers the telemetry ping process via the Job Scheduler.
     *
     * @param context The execution context provided by the Job Scheduler.
     */
    @Override
    public void execute(JobExecutionContext context) {
        // Step B: Check if the telemetry feature is enabled via settings
        if (!isEnabled) {
            log.debug("TelemetryPingJob skipped: wazuh.telemetry.enabled is set to false.");
            return;
        }

        // Concurrency control: prevent overlapping executions if a request hangs
        if (!this.semaphore.tryAcquire()) {
            log.warn("TelemetryPingJob (ID: {}) skipped because a previous task is still running.", 
                    context.getJobId());
            return;
        }

        // Offload network I/O to the generic thread pool to avoid blocking the scheduler
        this.threadPool.generic().execute(() -> {
            try {
                log.info("Executing Telemetry Ping Job (ID: {})", context.getJobId());

                // Step A: Retrieve environment Metadata
                String uuid = clusterService.state().metadata().clusterUUID();
                String version = Version.CURRENT.toString();

                // Step D: Perform the asynchronous HTTP request
                this.telemetryClient.sendPing(uuid, version);

            } catch (Exception e) {
                log.error("Error during Telemetry Ping Job (ID: {}): {}", 
                        context.getJobId(), e.getMessage());
            } finally {
                // Ensure the semaphore is always released to allow future executions
                this.semaphore.release();
            }
        });
    }

    /**
     * Checks if the telemetry job is currently active.
     *
     * @return true if the job is running, false otherwise.
     */
    public boolean isRunning() {
        return this.semaphore.availablePermits() == 0;
    }
}