package com.wazuh.commandmanager.jobscheduler;

import com.wazuh.commandmanager.CommandManagerPlugin;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public class JobDocument {
    private static final Logger log = LogManager.getLogger(JobDocument.class);

    public static void create(Client client, ThreadPool threadPool, String id, String jobName, Integer interval) {
        CompletableFuture<IndexResponse> completableFuture = new CompletableFuture<>();
        ExecutorService executorService = threadPool.executor(ThreadPool.Names.WRITE);
        CommandManagerJobParameter jobParameter = new CommandManagerJobParameter(
            jobName,
            new IntervalSchedule(Instant.now(), interval, ChronoUnit.MINUTES)
        );
        try {
            IndexRequest indexRequest = new IndexRequest()
                .index(CommandManagerPlugin.JOB_INDEX_NAME)
                .id(id)
                .source(jobParameter.toXContent(JsonXContent.contentBuilder(), null))
                .create(true);
            executorService.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored = threadPool.getThreadContext().stashContext()) {
                        IndexResponse indexResponse = client.index(indexRequest).actionGet();
                        completableFuture.complete(indexResponse);
                    } catch (Exception e) {
                        completableFuture.completeExceptionally(e);
                    }
                }
            );
        } catch (IOException e) {
            log.error("Failed to index command with ID {}: {}", id, e);
        }
    }
}
