package com.wazuh.contentmanager.jobscheduler.jobs;

import com.wazuh.contentmanager.jobscheduler.JobExecutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.jobscheduler.spi.JobExecutionContext;

import java.time.Instant;

/**
 * A sample implementation of a concrete Job.
 * This specific job simply prints a "Hello World" message to the logs.
 */
public class HelloWorldJob implements JobExecutor {
    private static final Logger log = LogManager.getLogger(HelloWorldJob.class);

    // Identifier used to route this specific job type
    public static final String JOB_TYPE = "hello-world-task";

    /**
     * Executes the logic for the Hello World job.
     * * @param context The execution context provided by the Job Scheduler.
     */
    @Override
    public void execute(JobExecutionContext context) {
        log.info("************************************************");
        log.info("* Hello World! - Executing Job ID: {}", context.getJobId());
        log.info("* Time: {}", Instant.now());
        log.info("************************************************");
    }
}
