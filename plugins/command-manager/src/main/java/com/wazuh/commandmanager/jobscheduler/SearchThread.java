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
import org.opensearch.search.builder.PointInTimeBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo;

/**
 * The class in charge of searching for PENDING commands and of submitting them to the destination client
 */
public class SearchThread implements Runnable {
    private static final Logger log = LogManager.getLogger(SearchThread.class);
    private final SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
    private SearchResponse currentPage = null;
    private final Client client;

    public SearchThread(Client client) {
        this.client = client;
    }

    /**
     * Retrieves a nested value from a Map<String, Object> in a (somewhat) safe way
     * @param map: The parent map to look at
     * @param key: The key our nested object is found under
     * @param type: The type we expect the nested object to be of
     * @return the nested object cast into the proper type
     * @param <T>: The type of the nested object
     */
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

    /**
     * Gets the last search result from a page
     * @param searchResponse: The search response page
     * @return the last SearchHit of a search page
     */
    public SearchHit getLastHit(SearchResponse searchResponse) {
        try {
            int resultsIndex = searchResponse.getHits().getHits().length - 1;
            if (resultsIndex > 0) {
                return searchResponse
                    .getHits()
                    .getHits()[resultsIndex];
            }
            else {
                return null;
            }
        } catch (Exception e) {
            log.error("Could not get the page's hits: {}", e.getMessage());
            // Return null in order for getSearchAfter() to know that
            // there are no more search results
            return null;
        }
    }

    /**
     * Iterates over search results, updating their status field and submitting them to the destination
     * @param searchResponse: The search results page
     * @throws IllegalStateException: Rethrown from updateStatusField()
     */
    public void handlePage(SearchResponse searchResponse) throws IllegalStateException {
        SearchHits searchHits = searchResponse.getHits();
        for (SearchHit hit : searchHits) {
            updateStatusField(this.client, hit, Status.SENT);
            deliverOrders(hit);
        }
    }

    private static void deliverOrders(SearchHit hit) {
        try ( XContentBuilder xContentBuilder = XContentFactory.jsonBuilder() ) {
            hit.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);
            HttpRestClientDemo.run("https://httpbin.org/post", xContentBuilder.toString());
        } catch (IOException e) {
            log.error("Error parsing hit contents: {}",e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void updateStatusField(Client client, SearchHit hit, Status status ) throws IllegalStateException {
        Map<String, Object> commandMap =
            getNestedValue(hit.getSourceAsMap(), "command", Map.class);
        commandMap.put(Command.STATUS, status);
        hit.getSourceAsMap().put("command", commandMap);
        IndexRequest indexRequest =
            new IndexRequest()
                .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                .source(hit.getSourceAsMap())
                .id(hit.getId());
        client.index(indexRequest).actionGet(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS * 1000);
    }

    public SearchResponse pitQuery(Client client, String index, Integer resultsPerPage, PointInTimeBuilder pointInTimeBuilder, Object[] searchAfter) throws IllegalStateException {
        SearchRequest searchRequest = new SearchRequest(index);
        TermQueryBuilder termQueryBuilder =
            QueryBuilders.termQuery(Command.COMMAND + "." + Command.STATUS + ".keyword", Status.PENDING);
        getSearchSourceBuilder()
            .query(termQueryBuilder)
            .size(resultsPerPage)
            .trackTotalHits(true)
            .timeout(TimeValue.timeValueSeconds(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS))
            .pointInTimeBuilder(pointInTimeBuilder);
        if( getSearchSourceBuilder().sorts() == null ) {
            getSearchSourceBuilder()
                .sort(Command.COMMAND + "." + Command.ORDER_ID + ".keyword", SortOrder.ASC)
                .sort(Command.COMMAND + "." + Command.TIMEOUT, SortOrder.ASC);
        }
        if (searchAfter != null) {
            getSearchSourceBuilder().searchAfter(searchAfter);
        }
        searchRequest.source(getSearchSourceBuilder());
        return client.search(searchRequest)
            .actionGet(TimeValue.timeValueSeconds(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS));
    }

    @Override
    public void run() {
        long consumableHits = 0L;
        boolean firstPage = true;
        PointInTimeBuilder pointInTimeBuilder = buildPit();
        do {
            try {
                setCurrentPage(
                    pitQuery(
                        this.client,
                        CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME,
                        CommandManagerPlugin.PAGE_SIZE,
                        pointInTimeBuilder,
                        getSearchAfter()
                    )
                );
                if (firstPage) {
                    consumableHits = totalHits();
                    firstPage = false;
                }
                if ( consumableHits > 0 ) {
                    handlePage(getCurrentPage());
                    consumableHits -= getPageLength();
                }
            }  catch (ArrayIndexOutOfBoundsException e) {
                log.error("ArrayIndexOutOfBoundsException retrieving page: {}", e.getMessage());
            } catch (IllegalStateException e) {
                log.error("IllegalStateException retrieving page: {}", e.getMessage());
            } catch (Exception e) {
                log.error("Generic exception retrieving page: {}", e.getMessage());
            }
        }
        while (consumableHits > 0);
    }

    private long getPageLength() {
        return getCurrentPage().getHits().getHits().length;
    }

    private long totalHits() throws NullPointerException {
        return Objects.requireNonNull(getCurrentPage().getHits().getTotalHits()).value;
    }

    private SearchSourceBuilder getSearchSourceBuilder() {
        return searchSourceBuilder;
    }

    private SearchResponse getCurrentPage() {
        return currentPage;
    }

    private void setCurrentPage(SearchResponse currentPage) {
        this.currentPage = currentPage;
    }

    private Object[] getSearchAfter() {
        if (getLastHit(getCurrentPage()) != null) {
            return getLastHit(getCurrentPage()).getSortValues();
        }
        else {
            return null;
        }
    }

    private PointInTimeBuilder buildPit() {
        CompletableFuture<CreatePitResponse> future = new CompletableFuture<>();
        ActionListener<CreatePitResponse> actionListener = new ActionListener<>() {
            @Override
            public void onResponse(CreatePitResponse createPitResponse) {
                future.complete(createPitResponse);
            }
            @Override
            public void onFailure(Exception e) {
                log.error(e.getMessage());
                future.completeExceptionally(e);
            }
        };
        this.client.createPit(
            new CreatePitRequest(
                CommandManagerPlugin.PIT_KEEPALIVE_SECONDS,
                false,
                CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME
            ),
            actionListener
        );
        try {
            return new PointInTimeBuilder(future.get().getId());
        } catch (Exception e ) {
            log.error(e.getMessage());
        }
        return null;
    }
}
