package com.wazuh.setup.jobscheduler;

import com.wazuh.setup.settings.PluginSettings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.threadpool.ThreadPool;

/**
 * Implements the ScheduledJobRunner interface, which exposes the runJob() method, which executes
 * the job's logic in its own thread.
 */
public class AgentJobRunner implements ScheduledJobRunner {

    private static final Logger log = LogManager.getLogger(AgentJobRunner.class);

    /** Singleton instance. */
    private static AgentJobRunner INSTANCE;

    /** OpenSearch's client. */
    private Client client;

    /** OpenSearch's cluster service. */
    private ClusterService clusterService;

    /** OpenSearch's thread pool. */
    private ThreadPool threadPool;

    /** Commands index repository. */
    //private CommandIndex indexManager;

    /** Private constructor. */
    private AgentJobRunner() {}

    /**
     * Singleton instance access method.
     *
     * @return the singleton instance.
     */
    public static AgentJobRunner getInstance() {
        if (AgentJobRunner.INSTANCE == null) {
            INSTANCE = new AgentJobRunner();
        }
        return INSTANCE;
    }

    @Override
    public void runJob(ScheduledJobParameter jobParameter, JobExecutionContext context) {
        if (!this.clusterService.state().routingTable().hasIndex(PluginSettings.getAgentsIndex())) {
            log.info(
                "{} index not yet created, not running command manager jobs",
                PluginSettings.getAgentsIndex());
            return;
        }
        final AgentStatusUpdateJob job = new AgentStatusUpdateJob(this.client);
        this.threadPool.generic().submit(job);
    }


    /**
     * Sets the commands index repository.
     *
     * @param indexManager the commands index repository.
     * @return invoking instance to allow concatenation of setWhatever() calls.

    public AgentJobRunner setIndexRepository(CommandIndex indexManager) {
        this.indexManager = indexManager;
        return getInstance();
    }*/

    /**
     * Sets the client.
     *
     * @param client OpenSearch's client.
     * @return invoking instance to allow concatenation of setWhatever() calls.
     */
    public AgentJobRunner setClient(Client client) {
        this.client = client;
        return getInstance();
    }

    /**
     * Sets the thread pool.
     *
     * @param threadPool OpenSearch's thread pool.
     * @return invoking instance to allow concatenation of setWhatever() calls.
     */
    public AgentJobRunner setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
        return getInstance();
    }
}
