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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.model.Consumer;
import com.wazuh.contentmanager.model.Document;

/** Class to manage the Context index. */
public class ContextIndex {
    private static final Logger log = LogManager.getLogger(ContextIndex.class);

    public static final String INDEX_NAME = "wazuh-context";
    public static final String CONTEXT_NAME = "vd_1.0.0";

    private final Client client;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;

    private final SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

    /**
     * Constructs a ContextIndex instance.
     *
     * @param client OpenSearch client instance to interact with the cluster.
     * @param clusterService OpenSearch cluster service instance to check index states.
     * @param threadPool An OpenSearch ThreadPool.
     */
    public ContextIndex(Client client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    /** Creates the context index if it does not exist. */
    public void createIndex() {
        if (!indexExists()) {
            Map<String, Object> source = createMapping();
            CreateIndexRequest request = new CreateIndexRequest(INDEX_NAME).mapping(source);
            CreateIndexResponse createIndexResponse =
                    this.client.admin().indices().create(request).actionGet();
            log.info(
                    "Index created successfully: {} {}",
                    createIndexResponse.index(),
                    createIndexResponse.isAcknowledged());
        }

        // Initialize the metadata of context
        Consumer consumer = new Consumer(0, null, "", "");
        Document document = new Document(consumer);
        indexDocument(document, CONTEXT_NAME);
    }

    /**
     * Checks if the wazuh-content index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean indexExists() {
        return this.clusterService.state().routingTable().hasIndex(INDEX_NAME);
    }

    /**
     * Index a Document object.
     *
     * @param document to index
     * @param id of document
     * @return CompletableFuture<RestStatus>
     */
    public CompletableFuture<RestStatus> indexDocument(Document document, String id) {
        final CompletableFuture<RestStatus> future = new CompletableFuture<>();
        final ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);

        executor.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored =
                            this.threadPool.getThreadContext().stashContext()) {
                        IndexRequest indexRequest = createIndexRequest(document, id);
                        log.info("Previously indexing document {}", id);
                        final RestStatus restStatus =
                                this.client.index(indexRequest).actionGet().status();
                        log.info("POST indexing document {}", id);
                        future.complete(restStatus);
                    } catch (Exception e) {
                        log.error("Error creating IndexRequest due to {}", e.getMessage());
                        future.completeExceptionally(e);
                    }
                });

        return future;
    }

    /**
     * Create an IndexRequest object from a Document object.
     *
     * @param document the document to create the IndexRequest for COMMAND_MANAGER_INDEX
     * @return an IndexRequest object
     * @throws IOException thrown by XContentFactory.jsonBuilder()
     */
    private IndexRequest createIndexRequest(Document document, String id) throws IOException {
        return new IndexRequest()
                .index(INDEX_NAME)
                .source(document.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .id(id)
                .create(true);
    }

    /**
     * Get a document from the index.
     *
     * @param contextName the id of the document
     * @return RestStatus of get
     */
    public CompletableFuture<RestStatus> get(String contextName) {
        final CompletableFuture<RestStatus> future = new CompletableFuture<>();
        final ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);
        final TermQueryBuilder termQueryBuilder = QueryBuilders.termQuery("_id", contextName);
        this.searchSourceBuilder.query(termQueryBuilder);

        executor.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored =
                            this.threadPool.getThreadContext().stashContext()) {
                        SearchRequest searchRequest =
                                createSearchRequest(this.searchSourceBuilder.trackTotalHits(true));

                        final SearchResponse searchResponse =
                                this.client.search(searchRequest).actionGet();

                        log.info("Result SEARCH: {}", searchResponse.toString());

                        final RestStatus restStatus = searchResponse.status();

                        future.complete(restStatus);

                        log.info(
                                "Found {} documents",
                                Objects.requireNonNull(searchResponse.getHits().getTotalHits())
                                        .value);
                    } catch (Exception e) {
                        log.error("Error creating SearchRequest due to {}", e.getMessage());
                        future.completeExceptionally(e);
                    }
                });
        return future;
    }

    /**
     * Get all documents
     *
     * @return el RestStatus of get all documents
     */
    public CompletableFuture<RestStatus> getAll() {
        final CompletableFuture<RestStatus> future = new CompletableFuture<>();
        final ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);

        executor.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored =
                            this.threadPool.getThreadContext().stashContext()) {
                        searchSourceBuilder.query(null);
                        SearchRequest searchRequest =
                                createSearchRequest(this.searchSourceBuilder.trackTotalHits(true));

                        final SearchResponse searchResponse =
                                this.client.search(searchRequest).actionGet();

                        log.info("Result SEARCH ALL: {}", searchResponse.toString());

                        final RestStatus restStatus = searchResponse.status();

                        future.complete(restStatus);

                        log.info(
                                "Found {} documents",
                                Objects.requireNonNull(searchResponse.getHits().getTotalHits())
                                        .value);
                    } catch (Exception e) {
                        log.error("Error creating SearchRequest due to {}", e.getMessage());
                        future.completeExceptionally(e);
                    }
                });

        return future;
    }

    /**
     * Create a SearchRequest object from a SearchSourceBuilder object.
     *
     * @param searchSourceBuilder builder to create the SearchRequest
     * @return SearchRequest
     */
    private SearchRequest createSearchRequest(SearchSourceBuilder searchSourceBuilder) {
        SearchRequest searchRequest = new SearchRequest(INDEX_NAME);
        searchRequest.source(searchSourceBuilder);

        return searchRequest;
    }

    /**
     * Update an existing document
     *
     * @param id of document
     * @param document to update the source of the previous document
     * @return UpdateResponse
     */
    public UpdateResponse update(String id, Document document) {
        return this.client.update(createUpdateRequest(id, document)).actionGet();
    }

    /**
     * Create an UpdateRequest object from a Document object.
     *
     * @param id of document
     * @param document to update
     * @return UpdateRequest
     */
    private UpdateRequest createUpdateRequest(String id, Document document) {
        UpdateRequest updateRequest = new UpdateRequest();
        updateRequest.index(INDEX_NAME);
        updateRequest.id(id);
        try {
            updateRequest.doc(
                    document.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
        } catch (IOException e) {
            log.error("Error creating IndexRequest due to {}", e.getMessage());
        }
        return updateRequest;
    }

    /**
     * Create the mapping for the content index
     *
     * @return Map<String, Object> with the mapping
     */
    private static Map<String, Object> createMapping() {
        Map<String, Object> properties = new HashMap<>();

        properties.put("offset", createProperty("integer"));
        properties.put("last_offset", createProperty("integer"));
        properties.put("snapshot", createProperty("text"));
        properties.put("hash", createProperty("text"));

        Map<String, Object> mapping = new HashMap<>();
        mapping.put("properties", properties);

        return mapping;
    }

    /**
     * Create a property for the content index
     *
     * @return Map<String, Object> with the property
     */
    private static Map<String, Object> createProperty(String type) {
        Map<String, Object> property = new HashMap<>();
        property.put("type", type);
        return property;
    }
}
