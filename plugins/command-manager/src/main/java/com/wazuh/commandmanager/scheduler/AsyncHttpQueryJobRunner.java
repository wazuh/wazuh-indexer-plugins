package com.wazuh.commandmanager.scheduler;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.config.reader.ConfigReader;
import com.wazuh.commandmanager.http.client.AsyncRequestRepository;
import com.wazuh.commandmanager.scheduler.model.AsyncHttpQueryRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.threadpool.ThreadPool;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.Future;

public class AsyncHttpQueryJobRunner implements ScheduledJobRunner {

    private static final String COMMAND_MANAGER_THREAD_POOL_NAME = CommandManagerPlugin.COMMAND_MANAGER_THREAD_POOL_NAME;
    private static final Logger logger = LogManager.getLogger(AsyncHttpQueryJobRunner.class);

    private static final AsyncHttpQueryJobRunner INSTANCE = new AsyncHttpQueryJobRunner();
    private ConfigReader configReader;

    public static AsyncHttpQueryJobRunner getJobRunnerInstance() {
        return INSTANCE;
    }

    private ClusterService clusterService;
    private ThreadPool threadPool;
    private Client client;
    //private AsyncQueryExecutorService asyncQueryExecutorService;

    private AsyncHttpQueryJobRunner() {
        // Singleton class, use getJobRunnerInstance method instead of constructor
    }

    public void loadJobResource(
        Client client,
        ClusterService clusterService,
        ThreadPool threadPool,
        ConfigReader configReader
        ) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.configReader = configReader;
    }

    private Future<SimpleHttpResponse> getAsyncHttpRequestFuture(ConfigReader configReader) {
        return AccessController.doPrivileged(
            (PrivilegedAction<Future<SimpleHttpResponse>>) () -> {
                try (AsyncRequestRepository asyncRequestRepository = AsyncRequestRepository.getInstance(configReader)){
                    return asyncRequestRepository.performAsyncRequest();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        );
    }

    @Override
    public void runJob(ScheduledJobParameter jobParameter, JobExecutionContext context) {
        // Parser will convert jobParameter to ScheduledAsyncQueryJobRequest
        if (!(jobParameter instanceof AsyncHttpQueryRequest)) {
            throw new IllegalStateException(
                "Job parameter is not instance of ScheduledAsyncQueryJobRequest, type: "
                    + jobParameter.getClass().getCanonicalName());
        }

        if (this.clusterService == null) {
            throw new IllegalStateException("ClusterService is not initialized.");
        }

        if (this.threadPool == null) {
            throw new IllegalStateException("ThreadPool is not initialized.");
        }

        if (this.client == null) {
            throw new IllegalStateException("Client is not initialized.");
        }

        if (this.configReader == null) {
            throw new IllegalStateException("ConfigReader is not initialized.");
        }

        Runnable runnable =
            () -> {
                try {
                    //doRefresh((AsyncHttpQueryRequest) jobParameter);
                    logger.info(getAsyncHttpRequestFuture(this.configReader).get().getBodyText());
                } catch (Throwable throwable) {
                    logger.error(throwable);
                }
            };
        threadPool.executor(COMMAND_MANAGER_THREAD_POOL_NAME).submit(runnable);
    }
}
