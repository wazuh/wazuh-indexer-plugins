/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.jobscheduler;

import com.wazuh.commandmanager.CommandManagerPlugin;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.index.reindex.ScrollableHitSource;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.function.IntConsumer;


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

    private CompletableFuture<SearchResponse> asyncSearch(SearchRequest searchRequest) {
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
        SearchRequest searchRequest = new SearchRequest(index);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

        TermQueryBuilder termQueryBuilder = QueryBuilders.termQuery("command.status.keyword","PENDING");
        searchSourceBuilder.query(termQueryBuilder)
            .size(resultsPerPage);
        searchRequest.source(searchSourceBuilder);

        asyncSearch(searchRequest)
            .thenAccept(
                CommandManagerJobRunner::handleSearchResponse
            )
            .exceptionally(
                e -> {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    PrintStream ps = new PrintStream(baos);
                    e.printStackTrace(ps);
                    log.error(baos.toString());
                    return null;
                }
            )
        ;
    }

    private static void handleSearchResponse(SearchResponse searchResponse) {
        SearchHits searchHits = searchResponse.getHits();
        for (SearchHit hit: searchHits) {
            log.info(Arrays.toString(hit.getSourceAsMap().entrySet().toArray()));
        }
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
            log.info("Running job");
            searchJob(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME, 10);
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
