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
import org.opensearch.common.unit.TimeValue;
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

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo;

public class SearchJob {
    private static final Logger log = LogManager.getLogger(SearchJob.class);
    private static SearchJob INSTANCE;
    private String pitId;
    private Object[] searchAfter = null;
    private SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
    private SearchResponse currentPage = null;

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

    public CompletableFuture<SearchResponse> futureSearch(Client client, SearchRequest searchRequest) {
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

    public SearchHit getLastHit(SearchResponse searchResponse) {
        return searchResponse
            .getHits()
            .getHits()[searchResponse.getHits().getHits().length - 1];
    }

    public void handlePage(Client client, SearchResponse searchResponse) throws IOException {
        SearchHits searchHits = searchResponse.getHits();
        for (SearchHit hit : searchHits) {
            updateStatusField(client, hit, Status.SENT);
            commandHttpRequest(hit);
        }
    }

    private static void commandHttpRequest(SearchHit hit) throws IOException {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder();
        hit.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);
        HttpRestClientDemo.run("https://httpbin.org/post", xContentBuilder.toString());
    }

    private void updateStatusField(Client client, SearchHit hit, Status status ) {
        Map<String, Object> commandMap =
            getNestedValue(hit.getSourceAsMap(), "command", Map.class);
        commandMap.put(Command.STATUS, status);
        hit.getSourceAsMap().put("command", commandMap);
        IndexRequest indexRequest =
            new IndexRequest()
                .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                .source(hit.getSourceAsMap())
                .id(hit.getId());
        client.index(
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

    public SearchResponse preparePitSearch(Client client, String index, Integer resultsPerPage, Object[] searchAfter) throws IllegalStateException {
        return client.search(
            pitSearchRequest(client, index, resultsPerPage, searchAfter)
        ).actionGet(TimeValue.timeValueSeconds(CommandManagerPlugin.SEARCH_QUERY_TIMEOUT));
    }

    private SearchRequest pitSearchRequest(Client client, String index, Integer resultsPerPage, Object[] searchAfter) {
        SearchRequest searchRequest = new SearchRequest(index);
        TermQueryBuilder termQueryBuilder =
            QueryBuilders.termQuery(Command.COMMAND + "." + Command.STATUS + ".keyword", Status.PENDING);
        getSearchSourceBuilder()
            .query(termQueryBuilder)
            .size(resultsPerPage)
            .trackTotalHits(true)
            .pointInTimeBuilder(
                PointInTime.getInstance(client, index).getPointInTimeBuilder()
            );
        if( getSearchSourceBuilder().sorts() == null ) {
            getSearchSourceBuilder()
                .sort(Command.COMMAND + "." + Command.ORDER_ID + ".keyword", SortOrder.ASC)
                .sort(Command.COMMAND + "." + Command.TIMEOUT, SortOrder.ASC);

        }
        if (searchAfter != null) {
            getSearchSourceBuilder().searchAfter(searchAfter);
        }
        searchRequest.source(getSearchSourceBuilder());
        return searchRequest;
    }

    public Runnable searchJobRunnable(Client client, String index, Integer resultsPerPage) {
        return () -> {
            long consumableHits = 0L;
            boolean firstPage = true;
            do {
                try {
                    setCurrentPage(
                        client,
                        index,
                        resultsPerPage
                    );
                    handlePage(client, getCurrentPage());
                } catch (IOException e) {
                    log.error("IOException retrieving page: {}", e.getMessage());
                } catch (IllegalStateException e) {
                    log.error("IllegalStateException retrieving page: {}", e.getMessage());
                } catch (RuntimeException e) {
                    log.error("RuntimeException retrieving page: {}", e.getMessage());
                    e.printStackTrace();
                } catch (Exception e) {
                    log.error("Generic exception retrieving page: {}", e.getMessage());
                }
                if (firstPage) {
                    if ( totalHits() < 1L ) {
                        break;
                    }
                    consumableHits = totalHits();
                    firstPage = false;
                }
                consumableHits -= getPageLength();
            }
            while (consumableHits > 0);
        };
    }

    private long getPageLength() {
        return getCurrentPage().getHits().getHits().length;
    }

    private long totalHits() throws NullPointerException {
        return Objects.requireNonNull(getCurrentPage().getHits().getTotalHits()).value;
    }

    private void setSearchSourceBuilder(SearchSourceBuilder searchSourceBuilder) {
        this.searchSourceBuilder = searchSourceBuilder;
    }

    private SearchSourceBuilder getSearchSourceBuilder() {
        return searchSourceBuilder;
    }

    private SearchResponse getCurrentPage() {
        return currentPage;
    }

    private void setCurrentPage(Client client, String index, Integer resultsPerPage) throws IOException, IllegalStateException {
        this.currentPage =
            preparePitSearch(
                client,
                index,
                resultsPerPage,
                getSearchAfter()
            );
    }

    private Object[] getSearchAfter() {
        if (getCurrentPage() == null) {
            return null;
        }
        else {
            return getLastHit(getCurrentPage()).getSortValues();
        }
    }
}
