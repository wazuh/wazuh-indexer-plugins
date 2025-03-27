/*
 * Copyright (C) 2024, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.setup.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;

import com.wazuh.setup.settings.PluginSettings;
import com.wazuh.setup.utils.IndexTemplateUtils;

/** Indexes the agent job to the Jobs index. */
public class JobDocument {
    private static final Logger log = LogManager.getLogger(JobDocument.class);
    private static final JobDocument INSTANCE = new JobDocument();

    private JobDocument() {}

    /**
     * Singleton instance access.
     *
     * @return singleton instance
     */
    public static JobDocument getInstance() {
        log.info("Getting JobDocument Instance");
        return INSTANCE;
    }

    /**
     * Writes a CommandManagerJobParameter type document to the jobs index
     *
     * @param clusterService the cluster's service
     * @param client the cluster's client
     * @param threadPool the cluster's threadPool
     * @param id the job ID to be used
     * @param jobName rhe name of the job
     * @param interval the interval the action is expected to run at
     * @return a CompletableFuture that will hold the IndexResponse.
     */
    public CompletableFuture<IndexResponse> create(
            ClusterService clusterService,
            Client client,
            ThreadPool threadPool,
            String id,
            String jobName,
            Integer interval) {
        log.info("Begin the JobDocument creation");
        CompletableFuture<IndexResponse> completableFuture = new CompletableFuture<>();
        ExecutorService executorService = threadPool.executor(ThreadPool.Names.WRITE);
        AgentJobParameter jobParameter =
                new AgentJobParameter(
                        jobName, new IntervalSchedule(Instant.now(), interval, ChronoUnit.MINUTES));
        try {
            IndexRequest indexRequest =
                    new IndexRequest()
                            .index(PluginSettings.getJobIndexName())
                            .id(id)
                            .source(jobParameter.toXContent(JsonXContent.contentBuilder(), null))
                            .create(true);
            log.info("Index request " + indexRequest.toString());
            executorService.submit(
                    () -> {
                        try (ThreadContext.StoredContext ignored =
                                threadPool.getThreadContext().stashContext()) {
                            log.info("INIT of Indexing agent with ID {}", id);
                            if (IndexTemplateUtils.isMissingIndexTemplate(
                                    clusterService, PluginSettings.getJobIndexTemplate())) {
                                IndexTemplateUtils.putIndexTemplate(client, PluginSettings.getJobIndexTemplate());
                            } else {
                                log.info(
                                        "Index template {} already exists. Skipping creation.",
                                        PluginSettings.getJobIndexName());
                            }
                            log.info("Index request before index " + indexRequest.toString());
                            IndexResponse indexResponse = client.index(indexRequest).actionGet();
                            completableFuture.complete(indexResponse);
                        } catch (Exception e) {
                            log.info("Complete excepcionally " + e.getMessage());
                            completableFuture.completeExceptionally(e);
                        }
                    });
        } catch (IOException e) {
            log.error("Failed to index agent with ID {}: {}", id, e);
        }
        try {
            log.info("Return completableFuture " + completableFuture.get().status());
        } catch (InterruptedException | ExecutionException e) {
            log.error("ERROR " + e.getMessage());
        }
        return completableFuture;
    }
}
