/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.jobscheduler;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.search.Scroll;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.threadpool.ThreadPool;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;


public class CommandManagerJobRunner implements ScheduledJobRunner {

    private static final Logger log = LogManager.getLogger(CommandManagerJobRunner.class);
    private static CommandManagerJobRunner INSTANCE;
    private ThreadPool threadPool;
    private Client client;
    private ClusterService clusterService;

    private CommandManagerJobRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public static CommandManagerJobRunner getJobRunnerInstance() {
        log.info("Getting Job Runner Instance");
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (CommandManagerJobRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new CommandManagerJobRunner();
            return INSTANCE;
        }
    }

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    private CompletableFuture<SearchResponse> asyncSearch(SearchRequest searchRequest, Scroll scroll) {
        CompletableFuture<SearchResponse> completableFuture = new CompletableFuture<>();
        ExecutorService executorService = this.threadPool.executor(ThreadPool.Names.SEARCH);
        executorService.submit(
            () -> {
                try {
                    SearchResponse searchResponse = client.search(searchRequest).actionGet();
                    completableFuture.complete(searchResponse);
                } catch (Exception e) {
                    completableFuture.completeExceptionally(e);
                }
            }
        );
        return completableFuture;
    }

    private void searchJob(String index, Integer resultsPerPage) {
        log.info("Running search job");
        SearchRequest searchRequest = new SearchRequest(index);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        TermQueryBuilder termQueryBuilder = QueryBuilders.termQuery("command.status.keyword","PENDING");
        searchSourceBuilder.query(termQueryBuilder)
            .size(resultsPerPage)
            .sort(Command.COMMAND + "." + Command.TIMEOUT, SortOrder.ASC);

        searchRequest
            .source(searchSourceBuilder)
            .scroll(scroll);

        asyncSearch(searchRequest, scroll)
            .thenAccept(
                CommandManagerJobRunner::handleSearchResponse
            )
            .exceptionally(
                e -> {
                    logStackTrace(e);
                    return null;
                }
            );
    }

    private static void handleSearchResponse(SearchResponse searchResponse) {
        SearchHits searchHits = searchResponse.getHits();
        for (SearchHit hit: searchHits) {
            log.info(Arrays.toString(hit.getSourceAsMap().entrySet().toArray()));
        }
    }

    private static void logStackTrace(Throwable e) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(byteArrayOutputStream);
        e.printStackTrace(ps);
        log.error(byteArrayOutputStream.toString());
    }

    private boolean indexExists(String indexName) {
        return this.clusterService.state().routingTable().hasIndex(indexName);
    }

    @Override
    public void runJob(ScheduledJobParameter jobParameter, JobExecutionContext context) {
        if ( ! indexExists(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME) ) {
            log.info("{} index not yet created, not running command manager jobs", CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
            return;
        }
        Runnable runnable = () -> {
            searchJob(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME, CommandManagerPlugin.COMMAND_BATCH_SIZE);
        };
        threadPool.generic().submit(runnable);
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public void setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
    }
}
