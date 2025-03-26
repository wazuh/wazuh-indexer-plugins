package com.wazuh.setup.jobscheduler;

import com.wazuh.setup.settings.PluginSettings;
import com.wazuh.setup.utils.IndexTemplateUtils;
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
import java.util.concurrent.ExecutorService;

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
            executorService.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored =
                             threadPool.getThreadContext().stashContext()) {
                        if (IndexTemplateUtils.isMissingIndexTemplate(
                            clusterService, PluginSettings.getJobIndexTemplate())) {
                            IndexTemplateUtils.putIndexTemplate(client, PluginSettings.getJobIndexTemplate());
                        } else {
                            log.info(
                                "Index template {} already exists. Skipping creation.",
                                PluginSettings.getJobIndexName());
                        }
                        IndexResponse indexResponse = client.index(indexRequest).actionGet();
                        completableFuture.complete(indexResponse);
                    } catch (Exception e) {
                        completableFuture.completeExceptionally(e);
                    }
                });
        } catch (IOException e) {
            log.error("Failed to index agent with ID {}: {}", id, e);
        }
        return completableFuture;
    }
}
