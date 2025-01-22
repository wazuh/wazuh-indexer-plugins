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
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

public class Search {
    private static final Logger log = LogManager.getLogger(Search.class);

    public static SearchHits syncSearch(
            NodeClient client, String index, String field, String value) {
        BoolQueryBuilder boolQuery =
                QueryBuilders.boolQuery().must(QueryBuilders.termQuery(field, value));
        return executeSyncSearch(client, index, boolQuery);
    }

    public static SearchHits syncSearch(
            NodeClient client, String index, BoolQueryBuilder boolQuery) {
        return executeSyncSearch(client, index, boolQuery);
    }

    private static SearchHits executeSyncSearch(
            NodeClient client, String index, BoolQueryBuilder boolQuery) {
        SearchRequest searchRequest = new SearchRequest(index);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(boolQuery);
        searchRequest.source(searchSourceBuilder);

        final CountDownLatch latch = new CountDownLatch(1);
        final SearchHits[] searchHits = new SearchHits[1];

        client.search(
                searchRequest,
                new ActionListener<SearchResponse>() {
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
