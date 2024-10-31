/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.jobscheduler;

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

import com.wazuh.commandmanager.CommandManagerPlugin;

public class JobDocument {
    private static final Logger log = LogManager.getLogger(JobDocument.class);
    private static JobDocument INSTANCE;

    private JobDocument() {}

    public static JobDocument getInstance() {
        log.info("Getting JobDocument Instance");
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (JobDocument.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new JobDocument();
            return INSTANCE;
        }
    }

    public CompletableFuture<IndexResponse> create(
            Client client, ThreadPool threadPool, String id, String jobName, Integer interval) {
        CompletableFuture<IndexResponse> completableFuture = new CompletableFuture<>();
        ExecutorService executorService = threadPool.executor(ThreadPool.Names.WRITE);
        CommandManagerJobParameter jobParameter =
                new CommandManagerJobParameter(
                        jobName, new IntervalSchedule(Instant.now(), interval, ChronoUnit.MINUTES));
        try {
            IndexRequest indexRequest =
                    new IndexRequest()
                            .index(CommandManagerPlugin.JOB_INDEX_NAME)
                            .id(id)
                            .source(jobParameter.toXContent(JsonXContent.contentBuilder(), null))
                            .create(true);
            executorService.submit(
                    () -> {
                        try (ThreadContext.StoredContext ignored =
                                threadPool.getThreadContext().stashContext()) {
                            IndexResponse indexResponse = client.index(indexRequest).actionGet();
                            completableFuture.complete(indexResponse);
                        } catch (Exception e) {
                            completableFuture.completeExceptionally(e);
                        }
                    });
        } catch (IOException e) {
            log.error("Failed to index command with ID {}: {}", id, e);
        }
        return completableFuture;
    }
}
