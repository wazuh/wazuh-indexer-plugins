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
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.threadpool.ThreadPool;

import java.util.concurrent.Semaphore;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.console.client.TelemetryClient;
import com.wazuh.contentmanager.jobscheduler.JobExecutor;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Job responsible for sending a periodic telemetry ping to the Wazuh CTI API. This heartbeat
 * includes the environment's unique UUID and the Indexer version.
 */
public class TelemetryPingJob implements JobExecutor {
    private static final Logger log = LogManager.getLogger(TelemetryPingJob.class);

    /** Unique identifier for routing this specific job type within the Job Scheduler. */
    public static final String JOB_TYPE = "telemetry-ping-task";

    /** Semaphore used to ensure only one instance of the job runs at a time. */
    private final Semaphore semaphore = new Semaphore(1);

    private final ThreadPool threadPool;
    private final ClusterService clusterService;
    private final TelemetryClient telemetryClient;
    private final Environment environment;

    /** Package-private constructor for dependency injection during unit tests. */
    TelemetryPingJob(
            Settings settings,
            ClusterService clusterService,
            ThreadPool threadPool,
            Environment environment,
            TelemetryClient telemetryClient) {
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.environment = environment;
        this.telemetryClient = telemetryClient;
    }

    /**
     * Constructs a new TelemetryPingJob.
     *
     * @param settings The OpenSearch node settings.
     * @param clusterService The service providing access to the cluster state (for UUID retrieval).
     * @param threadPool The thread pool manager used to offload network tasks.
     * @param environment The environment object used to extract version details.
     */
    public TelemetryPingJob(
            Settings settings,
            ClusterService clusterService,
            ThreadPool threadPool,
            Environment environment) {
        this(settings, clusterService, threadPool, environment, new TelemetryClient());
    }

    /**
     * Triggers the telemetry ping process via the Job Scheduler.
     *
     * @param context The execution context provided by the Job Scheduler.
     */
    @Override
    public void execute(JobExecutionContext context) {
        this.performPing(context.getJobId());
    }

    /** Manually triggers an immediate execution of the telemetry ping. */
    public void trigger() {
        this.performPing("manual-trigger");
    }

    /**
     * Internal method handling the actual execution logic and thread offloading. * @param executionId
     * An identifier for logging purposes (e.g., job ID or manual trigger flag).
     */
    private void performPing(String executionId) {
        // Dynamically fetch the current status from PluginSettings
        if (!PluginSettings.getInstance().isTelemetryEnabled()) {
            log.debug("TelemetryPingJob skipped: telemetry is disabled via settings.");
            return;
        }

        // Concurrency control: prevent overlapping executions if a request hangs
        if (!this.semaphore.tryAcquire()) {
            log.warn(
                    "TelemetryPingJob (ID: {}) skipped because a previous task is still running.",
                    executionId);
            return;
        }

        // Offload network I/O to the generic thread pool to avoid blocking the scheduler
        this.threadPool
                .generic()
                .execute(
                        () -> {
                            try {
                                log.info("Executing Telemetry Ping Job (ID: {})", executionId);

                                String uuid = this.clusterService.state().metadata().clusterUUID();
                                String version = ContentManagerPlugin.getVersion(this.environment);

                                this.telemetryClient.ping(uuid, version);

                            } catch (Exception e) {
                                log.error(
                                        "Error during Telemetry Ping Job (ID: {}): {}", executionId, e.getMessage());
                            } finally {
                                // Ensure the semaphore is always released to allow future executions
                                this.semaphore.release();
                            }
                        });
    }
}
