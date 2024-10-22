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
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.utils.LockService;
import org.opensearch.threadpool.ThreadPool;


public class CommandManagerJobRunner implements ScheduledJobRunner {

    private static final Logger log = LogManager.getLogger(CommandManagerJobRunner.class);
    private static CommandManagerJobRunner INSTANCE;
    private ThreadPool threadPool;

    private CommandManagerJobRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public static CommandManagerJobRunner getJobRunnerInstance() {

        log.info("Getting Job Runner Instance");
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

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    @Override
    public void runJob(ScheduledJobParameter jobParameter, JobExecutionContext context) {
        Runnable runnable = () -> {
            log.info("Running job");
        };
        //final LockService lockService = context.getLockService();
        //Runnable runnable = () -> {
        //    lockService.acquireLock(jobParameter, context, ActionListener.wrap(
        //        lock -> {
        //            log.info("Running Job");
        //            lockService.release(
        //                lock,
        //                ActionListener.wrap(
        //                    released -> {
        //                        log.info("Released lock for job {}", jobParameter.getName());
        //                    }, exception -> {
        //                        throw new IllegalStateException("Failed to release lock");
        //                    }
        //                )
        //            );
        //        }, exception -> {
        //            throw new IllegalStateException("Failed to acquire lock");
        //        }
        //    ));
        //};
        threadPool.generic().submit(runnable);
    }
}
