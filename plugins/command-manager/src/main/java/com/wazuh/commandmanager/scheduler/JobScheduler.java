package com.wazuh.commandmanager.scheduler;

import com.wazuh.commandmanager.config.reader.ConfigReader;
import com.wazuh.commandmanager.http.client.AsyncRequestRepository;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.lifecycle.Lifecycle;
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.lifecycle.LifecycleListener;
import org.opensearch.threadpool.ThreadPool;


import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

public class JobScheduler implements LifecycleComponent {

    private static final Logger logger = LogManager.getLogger(JobScheduler.class);
    private final ConfigReader configReader;

    public JobScheduler(ThreadPool threadPool, ConfigReader configReader) {
        this.configReader = configReader;
        start(threadPool);
    }

    private void start(ThreadPool threadPool) {
        ExecutorService executorService = threadPool.executor(ThreadPool.Names.GENERIC);
        Future<SimpleHttpResponse> future = AccessController.doPrivileged(
            (PrivilegedAction<Future<SimpleHttpResponse>>) () -> {
                try (AsyncRequestRepository asyncRequestRepository = new AsyncRequestRepository(configReader)){
                    return asyncRequestRepository.performAsyncRequest();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        );
        executorService.submit(
            () -> {
                while(!Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(5000);
                        logger.info("Running HTTP Request");
                        logger.info(future.get().getBodyText());

                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        logger.info("Exiting scheduler");
                        break;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        );
    }

    @Override
    public Lifecycle.State lifecycleState() {
        return null;
    }

    @Override
    public void addLifecycleListener(LifecycleListener lifecycleListener) {

    }

    @Override
    public void removeLifecycleListener(LifecycleListener lifecycleListener) {

    }

    @Override
    public void start() {

    }

    @Override
    public void stop() {

    }

    @Override
    public void close() {

    }
}
