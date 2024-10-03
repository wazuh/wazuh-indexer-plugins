package com.wazuh.commandmanager.scheduler;

import com.wazuh.commandmanager.config.reader.ConfigReader;
import com.wazuh.commandmanager.http.client.AsyncRequestRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.threadpool.ThreadPool;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public class JobScheduler {

    private static final Logger logger = LogManager.getLogger(JobScheduler.class);

    public JobScheduler(ThreadPool threadPool) {
        start(threadPool);
    }

    private void start(ThreadPool threadPool) {
        ExecutorService executorService = threadPool.executor(ThreadPool.Names.GENERIC);
        executorService.submit(
            () -> {
                while(!Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(5000);
                        logger.info("Running task");
                        ConfigReader configReader = new ConfigReader();
                        AsyncRequestRepository asyncRequestRepository = new AsyncRequestRepository(configReader);
                        asyncRequestRepository.performAsyncRequest()
                            .thenAccept(
                                logger::info
                            )
                            .exceptionally(
                                e -> {
                                    logger.error(e);
                                    return null;
                                }
                            );
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
}
