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

import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.index.shard.IndexingOperationListener;

import java.io.IOException;
import java.util.Objects;

import com.wazuh.contentmanager.ContentManagerPlugin;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;

/** Class to manage the Content Manager index. */
public class ContentIndex implements IndexingOperationListener {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    private static final String INDEX_NAME = "wazuh-content-snapshot";
    private final Client client;
    private final ClusterService clusterService;
    private final SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();


    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     * @param clusterService OpenSearch cluster service.
     */
    public ContentIndex(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    /** Creates a content index */
    public void createIndex() {
        if (!indexExists()) {
            CreateIndexRequest request = new CreateIndexRequest(INDEX_NAME);
            CreateIndexResponse createIndexResponse =
                    this.client.admin().indices().create(request).actionGet();
            log.info(
                    "Index created successfully: {} {}",
                    createIndexResponse.index(),
                    createIndexResponse.isAcknowledged());
        }
    }

    /**
     * Checks if the content index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean indexExists() {
        return this.clusterService.state().routingTable().hasIndex(INDEX_NAME);
    }

    public void indexDocument(XContentBuilder document) {
        try {
            IndexRequest indexRequest = createIndexRequest(document);
            this.client.index(indexRequest);
        } catch (IOException e) {
            log.error("Error creating IndexRequest due to {}", e.getMessage());
        }
    }

    /**
     * Create an IndexRequest object from a Document object.
     *
     * @param document the document to create the IndexRequest for COMMAND_MANAGER_INDEX
     * @return an IndexRequest object
     * @throws IOException thrown by XContentFactory.jsonBuilder()
     */
    private IndexRequest createIndexRequest(XContentBuilder document) throws IOException {
        return new IndexRequest()
                .index(INDEX_NAME)
                .source(document)
                .id(ContentManagerPlugin.CONTEXT_NAME)
                .create(true);
    }

    public void patchDocument(JsonObject document) {
        try {
            String id = String.valueOf(document.get("_id"));
            final TermQueryBuilder termQueryBuilder = QueryBuilders.termQuery("_id", ContentManagerPlugin.CONTEXT_NAME);
            this.searchSourceBuilder.query(termQueryBuilder);
            SearchRequest searchRequest = createSearchRequest(this.searchSourceBuilder.trackTotalHits(true));
            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();
            log.info("Found {} documents", Objects.requireNonNull(searchResponse.getHits().getTotalHits()).value);

            SearchHit hit = searchResponse.getHits().getAt(0);
            //add some think to the hit

            IndexRequest indexRequest = createIndexRequest(hit.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)).opType(DocWriteRequest.OpType.UPDATE);
            this.client.index(indexRequest);
        } catch (IOException e) {
            log.error("Error creating IndexRequest due to {}", e.getMessage());
        }
    }

    private SearchRequest createSearchRequest(SearchSourceBuilder searchSourceBuilder) {
        SearchRequest searchRequest = new SearchRequest(INDEX_NAME);
        searchRequest.source(searchSourceBuilder);

        return searchRequest;
    }

}
