package com.wazuh.contentmanager.jobscheduler;

import com.wazuh.contentmanager.jobscheduler.jobs.HelloWorldJob;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The main runner class that acts as a router.
 * It implements ScheduledJobRunner and delegates execution to specific
 * JobExecutor implementations based on the job type.
 */
public class ContentJobRunner implements ScheduledJobRunner {
    private static final Logger log = LogManager.getLogger(ContentJobRunner.class);
    private static ContentJobRunner INSTANCE;

    // A thread-safe map to hold registered executors
    private final Map<String, JobExecutor> executors = new ConcurrentHashMap<>();

    /**
     * Singleton accessor method.
     * Ensures only one instance of the runner exists.
     */
    public static synchronized ContentJobRunner getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new ContentJobRunner();
            INSTANCE.init();
        }
        return INSTANCE;
    }

    private ContentJobRunner() {}

    /**
     * Initialize default jobs.
     */
    private void init() {
        this.registerExecutor(HelloWorldJob.JOB_TYPE, new HelloWorldJob());
    }

    /**
     * Registers a new executor for a specific job type.
     * @param jobType The string identifier for the job type.
     * @param executor The implementation of the job logic.
     */
    public void registerExecutor(String jobType, JobExecutor executor) {
        this.executors.put(jobType, executor);
        log.info("Job registered: [{}] -> class [{}]", jobType, executor.getClass().getSimpleName());
    }

    /**
     * The entry point called by the Job Scheduler when a trigger fires.
     * @param job The job parameters containing the job type definition.
     * @param context The execution context.
     */
    @Override
    public void runJob(ScheduledJobParameter job, JobExecutionContext context) {
        // Validate that the job parameter is of the expected type
        if (!(job instanceof ContentJobParameter contentJob)) {
            log.warn("Received job is not an instance of ContentJobParameter");
            return;
        }

        String type = contentJob.getJobType();

        // Retrieve the specific executor for this job type
        JobExecutor executor = this.executors.get(type);

        if (executor != null) {
            try {
                log.info("Router: Delegating work for type [{}]", type);
                executor.execute(context);
            } catch (Exception e) {
                log.error("Error executing job [{}]: {}", type, e.getMessage(), e);
            }
        } else {
            log.warn("Router: No registered executor for type [{}]", type);
        }
    }
}
