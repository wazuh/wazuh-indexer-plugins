/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.utils.LockService;
import org.opensearch.plugins.Plugin;
import org.opensearch.threadpool.ThreadPool;

import java.util.List;
import java.util.UUID;

/**
 * A sample job runner class.
 * <p>
 * The job runner should be a singleton class if it uses OpenSearch client or other objects passed
 * from OpenSearch. Because when registering the job runner to JobScheduler plugin, OpenSearch has
 * not invoked plugins' createComponents() method. That is saying the plugin is not completely initialized,
 * and the OpenSearch {@link org.opensearch.client.Client}, {@link ClusterService} and other objects
 * are not available to plugin and this job runner.
 * <p>
 * So we have to move this job runner initialization to {@link Plugin} createComponents() method, and using
 * singleton job runner to ensure we register a usable job runner instance to JobScheduler plugin.
 * <p>
 * This sample job runner takes the "indexToWatch" from job parameter and logs that index's shards.
 */
public class CommandManagerJobRunner implements ScheduledJobRunner {

    private static final Logger log = LogManager.getLogger(CommandManagerJobRunner.class);

    private static CommandManagerJobRunner INSTANCE;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private Client client;

    private CommandManagerJobRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public static CommandManagerJobRunner getJobRunnerInstance() {
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

    public void setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
    }

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public void setClient(Client client) {
        this.client = client;
    }


    @Override
    public void runJob(ScheduledJobParameter jobParameter, JobExecutionContext context) {
        if (!(jobParameter instanceof CommandManagerJobParameter)) {
            throw new IllegalStateException(
                    "Job parameter is not instance of SampleJobParameter, type: " + jobParameter.getClass().getCanonicalName()
            );
        }

        if (this.clusterService == null) {
            throw new IllegalStateException("ClusterService is not initialized.");
        }

        if (this.threadPool == null) {
            throw new IllegalStateException("ThreadPool is not initialized.");
        }

        final LockService lockService = context.getLockService();

        Runnable runnable = () -> {
            if (jobParameter.getLockDurationSeconds() != null) {
                lockService.acquireLock(jobParameter, context, ActionListener.wrap(lock -> {
                    if (lock == null) {
                        return;
                    }

                    CommandManagerJobParameter parameter = (CommandManagerJobParameter) jobParameter;
                    StringBuilder msg = new StringBuilder();
                    msg.append("Watching index ").append(parameter.getIndexToWatch()).append("\n");

                    List<ShardRouting> shardRoutingList = this.clusterService
                            .state()
                            .routingTable()
                            .allShards(parameter.getIndexToWatch());

                    for (ShardRouting shardRouting : shardRoutingList) {
                        msg.append(shardRouting.shardId().getId())
                                .append("\t")
                                .append(shardRouting.currentNodeId())
                                .append("\t")
                                .append(shardRouting.active() ? "active" : "inactive")
                                .append("\n");
                    }
                    log.info(msg.toString());
                    runTaskForIntegrationTests(parameter);
                    runTaskForLockIntegrationTests(parameter);

                    lockService.release(
                            lock,
                            ActionListener.wrap(released -> {
                                log.info("Released lock for job {}", jobParameter.getName());
                            }, exception -> {
                                throw new IllegalStateException("Failed to release lock.");
                            })
                    );
                }, exception -> {
                    throw new IllegalStateException("Failed to acquire lock.");
                }));
            }
        };

        threadPool.generic().submit(runnable);
    }

    private void runTaskForIntegrationTests(CommandManagerJobParameter jobParameter) {
        this.client.index(
                new IndexRequest(jobParameter.getIndexToWatch()).id(UUID.randomUUID().toString())
                        .source("{\"message\": \"message\"}", XContentType.JSON)
        );
    }

    private void runTaskForLockIntegrationTests(CommandManagerJobParameter jobParameter) throws InterruptedException {
        if (jobParameter.getName().equals("sample-job-lock-test-it")) {
            Thread.sleep(180000);
        }
    }
}
