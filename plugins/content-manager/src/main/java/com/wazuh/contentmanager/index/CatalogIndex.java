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
package com.wazuh.contentmanager.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;

/** Class to manage the Context index. */
public class CatalogIndex {
    private static final Logger log = LogManager.getLogger(CatalogIndex.class);

    public static final String CONSUMER_INFO_INDEX = "wazuh-context";

    private final Client client;

    public CatalogIndex(Client client) {
        this.client = client;
    }

    /**
     * Index CTI API consumer information
     *
     * @param consumerInfo Model containing information parsed from the CTI API
     */
    public void index(ConsumerInfo consumerInfo) {

        IndexRequest indexRequest = null;
        try {
            indexRequest =
                    new IndexRequest()
                            .index(CONSUMER_INFO_INDEX)
                            .source(
                                    consumerInfo.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .id(consumerInfo.getContext())
                            .create(true);
        } catch (IOException e) {
            log.error("Error creating Catalog IndexRequest: {}", e.getMessage());
        }

        this.client.index(
                indexRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        log.info(
                                "CTI Catalog Context {}, indexed with status {}",
                                indexResponse.getId(),
                                indexResponse.status());
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to index CTI Catalog Context {}, Exception: {}", consumerInfo.getContext(), e);
                    }
                });
    }

    /**
     * Get a context off its index
     *
     * @param contextName ID of the context to be retrieved
     * @return A completable future holding the response of the query
     */
    public CompletableFuture<SearchResponse> get(String contextName) {

        final TermQueryBuilder termQueryBuilder = QueryBuilders.termQuery("_id", contextName);

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(termQueryBuilder);

        SearchRequest searchRequest = new SearchRequest(CONSUMER_INFO_INDEX);
        searchRequest.source(searchSourceBuilder);

        CompletableFuture<SearchResponse> future = new CompletableFuture<>();

        this.client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse searchResponse) {
                        log.info(
                                "Retrieved CTI Catalog Context {} from index with status {}",
                                contextName,
                                searchResponse.status());
                        future.complete(searchResponse);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to retrieve CTI Catalog Context {}, Exception: {}", contextName, e);
                        future.completeExceptionally(e);
                    }
                });
        return future;
    }
}
