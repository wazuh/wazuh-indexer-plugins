/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.jobscheduler;

import com.wazuh.commandmanager.auth.AuthCredentials;
import com.wazuh.commandmanager.model.Status;
import com.wazuh.commandmanager.settings.PluginSettings;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.*;
import org.opensearch.client.Client;
import org.opensearch.common.Nullable;
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
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo;
import reactor.util.annotation.NonNull;

/**
 * The class in charge of searching for PENDING commands and of submitting them to the destination client
 */
public class SearchThread implements Runnable {
    private static final Logger log = LogManager.getLogger(SearchThread.class);
    public static final String COMMAND_STATUS_FIELD = Command.COMMAND + "." + Command.STATUS + ".keyword";
    public static final String COMMAND_ORDERID_FIELD = Command.COMMAND + "." + Command.ORDER_ID + ".keyword";
    public static final String COMMAND_TIMEOUT_FIELD = Command.COMMAND + "." + Command.TIMEOUT;
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
            setSentStatus(hit);
            deliverOrders(hit);
        }
    }

    private static void deliverOrders(SearchHit hit) {
        try ( XContentBuilder xContentBuilder = XContentFactory.jsonBuilder() ) {
            hit.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);
            HttpRestClientDemo.run("https://httpbin.org/post", xContentBuilder.toString());
            PluginSettings settings = PluginSettings.getInstance();
            HttpRestClient.getInstance().post(
                URI.create(settings.getUri()),
                xContentBuilder.toString(),
                hit.getId(),
                new AuthCredentials(
                    settings.getAuthUsername(),
                    settings.getAuthPassword()
                ).getAuthAsHeaders()
            );
        } catch (IOException e) {
            log.error("Error parsing hit contents: {}",e.getMessage());
        }
    }

    /**
     * Retrieves the hit's contents and updates the command.status field to "SENT"
     * @param hit: The page's result we are to update
     * @throws IllegalStateException: Rethrown this from actionGet
     */
    @SuppressWarnings("unchecked")
    private void setSentStatus(SearchHit hit) throws IllegalStateException {
        Map<String, Object> commandMap =
            getNestedValue(hit.getSourceAsMap(), CommandManagerPlugin.COMMAND_DOCUMENT_PARENT_OBJECT_NAME, Map.class);
        commandMap.put(Command.STATUS, Status.SENT);
        hit.getSourceAsMap().put(CommandManagerPlugin.COMMAND_DOCUMENT_PARENT_OBJECT_NAME, commandMap);
        IndexRequest indexRequest =
            new IndexRequest()
                .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                .source(hit.getSourceAsMap())
                .id(hit.getId());
        this.client.index(indexRequest).actionGet(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS * 1000);
    }

    /**
     * Runs a PIT style query against the Commands index
     *
     * @param pointInTimeBuilder: A pit builder object used to run the query
     * @param searchAfter: An array of objects containing the last page's values of the sort fields
     * @return The search response
     * @throws IllegalStateException: Rethrown from actionGet()
     */
    public SearchResponse pitQuery(
        @NonNull PointInTimeBuilder pointInTimeBuilder,
        @Nullable Object[] searchAfter
    ) throws IllegalStateException {
        SearchRequest searchRequest = new SearchRequest(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
        TermQueryBuilder termQueryBuilder =
            QueryBuilders.termQuery(SearchThread.COMMAND_STATUS_FIELD, Status.PENDING);
        TimeValue timeout = TimeValue.timeValueSeconds(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS);
        this.searchSourceBuilder
            .query(termQueryBuilder)
            .size(CommandManagerPlugin.PAGE_SIZE)
            .trackTotalHits(true)
            .timeout(timeout)
            .pointInTimeBuilder(pointInTimeBuilder);
        if( this.searchSourceBuilder.sorts() == null ) {
            this.searchSourceBuilder
                .sort(SearchThread.COMMAND_ORDERID_FIELD, SortOrder.ASC)
                .sort(SearchThread.COMMAND_TIMEOUT_FIELD, SortOrder.ASC);
        }
        if (searchAfter != null) {
            this.searchSourceBuilder.searchAfter(searchAfter);
        }
        searchRequest.source(this.searchSourceBuilder);
        return this.client.search(searchRequest)
            .actionGet(timeout);
    }

    @Override
    public void run() {
        long consumableHits = 0L;
        boolean firstPage = true;
        PointInTimeBuilder pointInTimeBuilder = buildPit();
        do {
            try {
                this.currentPage = pitQuery(
                    pointInTimeBuilder,
                    getSearchAfter()
                );
                if (firstPage) {
                    consumableHits = totalHits();
                    firstPage = false;
                }
                if ( consumableHits > 0 ) {
                    handlePage(this.currentPage);
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
        return this.currentPage.getHits().getHits().length;
    }

    private long totalHits() {
        if (this.currentPage.getHits().getTotalHits() != null) {
            log.warn("Query did not return any hits: totalHits is null");
            return this.currentPage.getHits().getTotalHits().value;
        }
        else {
            return 0;
        }
    }

    private Object[] getSearchAfter() {
        if (getLastHit(this.currentPage) != null) {
            return getLastHit(this.currentPage).getSortValues();
        }
        else {
            return null;
        }
    }

    /**
     * Prepares a PointInTimeBuilder object to be used in a search
     * @return a PointInTimeBuilder or null
     */
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
        } catch (CancellationException e ) {
            log.error("Building PIT was cancelled: {}",e.getMessage());
        } catch (ExecutionException e ) {
            log.error("Error building PIT: {}",e.getMessage());
        } catch (InterruptedException e ) {
            log.error("Building PIT was interrupted: {}",e.getMessage());
        }
        return null;
    }
}
