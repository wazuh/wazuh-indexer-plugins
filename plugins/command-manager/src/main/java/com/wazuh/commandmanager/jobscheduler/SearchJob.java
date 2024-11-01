/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.jobscheduler;

import com.wazuh.commandmanager.model.Status;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.*;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo;

public class SearchJob {
    private static final Logger log = LogManager.getLogger(SearchJob.class);
    private static SearchJob INSTANCE;
    private ThreadPool threadPool;
    private Client client;
    private String pitId;
    private Object[] searchAfter;
    private SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
    private final PointInTime pointInTime = PointInTime.getInstance();
    private SearchResponse searchResponse;

    public void setPitId(String pitId) {
        this.pitId = pitId;
    }

    public String getPitId() {
        return pitId;
    }

    public static SearchJob getInstance() {
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

    public CompletableFuture<SearchResponse> simpleSearch(String index, Integer resultsPerPage) {
        setSearchRequest(index, Command.COMMAND + "." + Command.STATUS, Status.PENDING.toString(), resultsPerPage);
        //ExecutorService executorService = this.threadPool.executor(ThreadPool.Names.SEARCH);
        //executorService.submit(
        //    () -> {
        //        try {
        //            SearchResponse searchResponse = client.search(searchRequest).actionGet();
        //            completableFuture.complete(searchResponse);
        //        } catch (Exception e) {
        //            completableFuture.completeExceptionally(e);
        //        }
        //    });
        return CompletableFuture.completedFuture(client.search(searchRequest).actionGet());
    }

    @SuppressWarnings("Unchecked")
    public static <T> T getNestedValue(Map<String, Object> map, String key, Class<T> type) {
        Object value = map.get(key);
        if (type.isInstance(value)) {
            return type.cast(value);
        } else {
            throw new ClassCastException(
                "Expected "
                    + type
                    + " but found "
                    + (value != null ? value.getClass() : "null"));
        }
    }

    public Object[] getLastItemSortValues(SearchResponse searchResponse) {
        return searchResponse
            .getHits()
            .getHits()[searchResponse.getHits().getHits().length - 1]
            .getSortValues();
    }

    public Object[] handleFirstPage(SearchResponse searchResponse) throws Exception {
        SearchHits searchHits = searchResponse.getHits();
        for (SearchHit hit : searchHits) {
            updateStatusField(hit, Status.SENT);
            commandHttpRequest(hit);
        }
        return getLastItemSortValues(searchResponse);
    }

    public void loopThroughPages() throws Exception {
        setSearchResponse(
            preparePitSearch(
                CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME,
                CommandManagerPlugin.COMMAND_BATCH_SIZE
            )
        );

        Object[] lastSortValues = handleFirstPage(getSearchResponse());
        boolean hasNext = true;
        while (hasNext) {

        }

    }

    private static void commandHttpRequest(SearchHit hit) throws IOException {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder();
        hit.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);
        HttpRestClientDemo.run("https://httpbin.org/post", xContentBuilder.toString());
    }

    private void updateStatusField(SearchHit hit, Status status ) {
        Map<String, Object> commandMap =
            getNestedValue(hit.getSourceAsMap(), "command", Map.class);
        commandMap.put(Command.STATUS, status);
        hit.getSourceAsMap().put("command", commandMap);
        IndexRequest indexRequest =
            new IndexRequest()
                .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                .source(hit.getSourceAsMap())
                .id(hit.getId());
        this.client.index(
            indexRequest,
            new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse indexResponse) {
                    log.debug("Updated command with document id: {}", hit.getId());
                }

                @Override
                public void onFailure(Exception e) {
                    log.error(e);
                }
            });
    }

    private void search(String index, String query, Integer size) {


    }

    public SearchResponse preparePitSearch(String index, Integer resultsPerPage) {
        SearchRequest searchRequest = new SearchRequest(index);
        TermQueryBuilder termQueryBuilder =
            QueryBuilders.termQuery(Command.STATUS + ".keyword", Status.PENDING);
        getSearchSourceBuilder()
            .query(termQueryBuilder)
            .size(resultsPerPage)
            .sort(Command.COMMAND + "." + Command.ORDER_ID, SortOrder.ASC)
            .sort(Command.COMMAND + "." + Command.TIMEOUT, SortOrder.ASC)
            .pointInTimeBuilder(
                this.pointInTime.createPit(this.client, index)
            );
        searchRequest.source(getSearchSourceBuilder());
        return  this.client.search(searchRequest).actionGet();
    }

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public SearchSourceBuilder getSearchSourceBuilder() {
        return searchSourceBuilder;
    }

    public void setSearchSourceBuilder(SearchSourceBuilder searchSourceBuilder) {
        this.searchSourceBuilder = searchSourceBuilder;
    }

    public SearchResponse getSearchResponse() {
        return searchResponse;
    }

    public void setSearchResponse(SearchResponse searchResponse) {
        this.searchResponse = searchResponse;
    }

}
