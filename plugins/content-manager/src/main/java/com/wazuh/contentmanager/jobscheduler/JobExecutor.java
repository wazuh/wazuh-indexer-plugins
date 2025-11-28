package com.wazuh.contentmanager.jobscheduler;

import org.opensearch.jobscheduler.spi.JobExecutionContext;

/**
 * Interface that defines the contract for all job executions.
 * Any specific task must implement this interface.
 */
public interface JobExecutor {

    /**
     * Trigger the execution of the job logic.
     * @param context Contains metadata about the job execution (e.g., Job ID).
     */
    void execute(JobExecutionContext context);
}
