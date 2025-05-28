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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.transport.client.support.AbstractClient;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;

import java.util.*;
import java.util.concurrent.CountDownLatch;

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
