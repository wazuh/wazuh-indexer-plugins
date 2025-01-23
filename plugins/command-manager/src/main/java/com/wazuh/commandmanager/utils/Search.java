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
package com.wazuh.commandmanager.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.support.AbstractClient;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.PointInTimeBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;

import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;

/** Utility class for performing generic search operations on the OpenSearch cluster. */
public class Search {
    private static final Logger log = LogManager.getLogger(Search.class);

    /**
     * Executes a synchronous search query on the specified index using a term query.
     *
     * @param client the AbstractClient used to execute the search query.
     * @param index the name of the index to search.
     * @param field the field to query.
     * @param value the value to search for in the specified field.
     * @return SearchHits object containing the search results.
     */
    public static SearchHits syncSearch(
            AbstractClient client, String index, String field, String value) {
        BoolQueryBuilder boolQuery =
                QueryBuilders.boolQuery().must(QueryBuilders.termQuery(field, value));
        return executeSearch(client, index, boolQuery);
    }

    /**
     * Executes a synchronous search query on the specified index using a boolean query.
     *
     * @param client the AbstractClient used to execute the search query.
     * @param index the name of the index to search.
     * @param boolQuery the boolean query to execute.
     * @return SearchHits object containing the search results.
     */
    public static SearchHits syncSearch(
            AbstractClient client, String index, BoolQueryBuilder boolQuery) {
        return executeSearch(client, index, boolQuery);
    }

    /**
     * Executes a synchronous search query on the specified index.
     *
     * @param client the AbstractClient used to execute the search query.
     * @param index the name of the index to search.
     * @param boolQuery the boolean query to execute.
     * @return SearchHits object containing the search results.
     */
    private static SearchHits executeSearch(
            AbstractClient client, String index, BoolQueryBuilder boolQuery) {
        SearchRequest searchRequest = new SearchRequest(index);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(boolQuery);
        searchRequest.source(searchSourceBuilder);

        final CountDownLatch latch = new CountDownLatch(1);
        final SearchHits[] searchHits = new SearchHits[1];

        client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse searchResponse) {
                        searchHits[0] = searchResponse.getHits();
                        latch.countDown();
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("", e);
                        latch.countDown();
                    }
                });
        try {
            latch.await(); // Wait for the search to complete
        } catch (InterruptedException e) {
            log.error("Interrupted while waiting for search to complete", e);
        }
        return searchHits[0];
    }

    /**
     * Executes a PIT style query on the specified index using a term query.
     *
     * @param client the Client used to execute the search query.
     * @param index the name of the index to search.
     * @param field the field to query.
     * @param value the value to search for in the specified field.
     * @param pitBuilder the PointInTimeBuilder used for the query.
     * @param searchAfter an array of objects containing the last page's values of the sort fields.
     * @param timeout the timeout value for the search query.
     * @param pageSize the size of each page of results.
     * @return the SearchResponse object containing the search results.
     */
    public static SearchResponse executePitQuery(
            Client client,
            String index,
            String field,
            String value,
            PointInTimeBuilder pitBuilder,
            Object[] searchAfter,
            TimeValue timeout,
            int pageSize,
            String sortField,
            SortOrder sortOrder) {

        SearchRequest searchRequest = new SearchRequest(index);
        BoolQueryBuilder boolQuery =
                QueryBuilders.boolQuery().must(QueryBuilders.termQuery(field, value));

        SearchSourceBuilder searchSourceBuilder =
                new SearchSourceBuilder()
                        .query(boolQuery)
                        .size(pageSize)
                        .trackTotalHits(true)
                        .timeout(timeout)
                        .pointInTimeBuilder(pitBuilder);

        if (searchSourceBuilder.sorts() == null) {
            searchSourceBuilder.sort(sortField, sortOrder);
        }
        if (searchAfter.length > 0) {
            searchSourceBuilder.searchAfter(searchAfter);
        }
        searchRequest.source(searchSourceBuilder);

        return client.search(searchRequest).actionGet(timeout);
    }

    /**
     * Retrieves the searchAfter values from a SearchResponse.
     *
     * @param searchResponse the SearchResponse containing the hits.
     * @return an Optional containing the searchAfter values, or an empty Optional if not found.
     */
    public static Optional<Object[]> getSearchAfter(SearchResponse searchResponse) {
        if (searchResponse == null) {
            return Optional.empty();
        }
        try {
            final List<SearchHit> hits = List.of(searchResponse.getHits().getHits());
            if (hits.isEmpty()) {
                log.warn("Empty hits page, not getting searchAfter values.");
                return Optional.empty();
            }
            return Optional.ofNullable(hits.get(hits.size() - 1).getSortValues());
        } catch (NullPointerException | NoSuchElementException e) {
            log.error("Could not get the page's searchAfter values: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Builds a PointInTimeBuilder for use in PIT queries.
     *
     * @param client the Client used to create the PIT.
     * @param pitKeepAlive the keep-alive duration for the PIT.
     * @param index the name of the index for which the PIT is created.
     * @return a PointInTimeBuilder initialized with the PIT ID, or null if an error occurs.
     */
    public static PointInTimeBuilder buildPit(Client client, TimeValue pitKeepAlive, String index) {
        final CompletableFuture<CreatePitResponse> future = new CompletableFuture<>();
        final ActionListener<CreatePitResponse> actionListener =
                new ActionListener<>() {
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
        client.createPit(new CreatePitRequest(pitKeepAlive, false, index), actionListener);
        try {
            return new PointInTimeBuilder(future.get().getId());
        } catch (CancellationException e) {
            log.error("Building PIT was cancelled: {}", e.getMessage());
        } catch (ExecutionException e) {
            log.error("Error building PIT: {}", e.getMessage());
        } catch (InterruptedException e) {
            log.error("Building PIT was interrupted: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Retrieves a nested object from a map.
     *
     * @param map the map containing the nested object.
     * @param key the key of the nested object.
     * @param type the expected type of the nested object.
     * @param <T> the type parameter.
     * @return the nested object if found, null otherwise.
     * @throws ClassCastException if the nested object is not of the expected type.
     */
    public static <T> T getNestedObject(Map<String, Object> map, String key, Class<T> type) {
        final Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (type.isInstance(value)) {
            // Make a defensive copy for supported types like Map or List
            if (value instanceof Map) {
                return type.cast(new HashMap<>((Map<?, ?>) value));
            } else if (value instanceof List) {
                return type.cast(new ArrayList<>((List<?>) value));
            }
            // Return the value directly if it is immutable (e.g., String, Integer)
            return type.cast(value);
        } else {
            throw new ClassCastException(
                    "Expected " + type.getName() + " but found " + value.getClass().getName());
        }
    }
}
