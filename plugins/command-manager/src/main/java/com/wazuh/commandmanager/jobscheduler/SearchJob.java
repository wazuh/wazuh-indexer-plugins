package com.wazuh.commandmanager.jobscheduler;

import com.wazuh.commandmanager.model.Command;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.*;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
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

public class SearchJob {
    private static final Logger log = LogManager.getLogger(SearchJob.class);
    private static SearchJob INSTANCE;
    private ThreadPool threadPool;
    private Client client;
    private String scrollId;
    private SearchResponse searchResponse;

    public static SearchJob getSearchJobInstance() {
        log.info("Getting Job Runner Instance");
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (SearchJob.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new SearchJob();
            return INSTANCE;
        }
    }

    private CompletableFuture<SearchResponse> search(SearchRequest searchRequest) {
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

    private CompletableFuture<SearchResponse> scrollSearch(SearchScrollRequest searchScrollRequest) {
        CompletableFuture<SearchResponse> completableFuture = new CompletableFuture<>();
        ExecutorService executorService = this.threadPool.executor(ThreadPool.Names.SEARCH);
        executorService.submit(
            () -> {
                try {
                    SearchResponse searchResponse = client.searchScroll(searchScrollRequest).actionGet();
                    completableFuture.complete(searchResponse);
                } catch (Exception e) {
                    completableFuture.completeExceptionally(e);
                }
            }
        );
        return completableFuture;
    }

    private static void handleSearchResponse(SearchResponse searchResponse) {
        SearchHits searchHits = searchResponse.getHits();
        for (SearchHit hit: searchHits) {
            log.info(Arrays.toString(hit.getSourceAsMap().entrySet().toArray()));
        }
    }

    public void searchJob(String index, Integer resultsPerPage) {
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

        search(searchRequest)
            .thenAccept(
                this::setSearchResponse
            )
            .exceptionally(
                e -> {
                    logStackTrace(e);
                    return null;
                }
            );

        setScrollId(searchResponse);
        while ( searchResponse.getHits().getHits().length > 0 ) {
            handleSearchResponse(searchResponse);
            SearchScrollRequest searchScrollRequest = new SearchScrollRequest(scrollId);
            searchScrollRequest.scroll(scroll);
            scrollSearch(searchScrollRequest)
                .thenAccept(
                    this::setSearchResponse
                )
                .exceptionally(
                    e -> {
                        logStackTrace(e);
                        return null;
                    }
                );
            setScrollId(searchResponse);
        }
        ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
        clearScrollRequest.addScrollId(scrollId);
        client.clearScroll(clearScrollRequest, new ActionListener<ClearScrollResponse>() {
            @Override
            public void onResponse(ClearScrollResponse clearScrollResponse) {
                log.info("Scroll request cleared");
            }

            @Override
            public void onFailure(Exception e) {
                logStackTrace(e);
            }
        });
    }

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    private void setScrollId(SearchResponse searchResponse) {
        this.scrollId = searchResponse.getScrollId();
    }

    public void setSearchResponse(SearchResponse searchResponse) {
        this.searchResponse = searchResponse;
    }

    private static void logStackTrace(Throwable e) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(byteArrayOutputStream);
        e.printStackTrace(ps);
        log.error(byteArrayOutputStream.toString());
    }
}
