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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.model.GenericDocument;

/** Class to manage the Content Manager index. */
public class ContentIndex {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    private static final String INDEX_NAME = "wazuh-content";

    private final Client client;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;

    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     * @param clusterService OpenSearch cluster service.
     * @param threadPool An OpenSearch ThreadPool.
     */
    public ContentIndex(Client client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    /** Creates a wazuh-content-manager index */
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

        // Initialize to test
        Map<String, Object> source = new HashMap<>();
        String content = "test";
        source.put("content", content);
        Integer content2 = 7;
        source.put("content2", content2);
        GenericDocument genericDocument = new GenericDocument("id_test-154", source);
        indexDocument(genericDocument);
    }

    /**
     * Checks if the wazuh-content-manager index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean indexExists() {
        return this.clusterService.state().routingTable().hasIndex(INDEX_NAME);
    }

    /**
     * Index a Document object.
     *
     * @param document the XContentBuilder document to index in wazuh-content-manager
     */
    public CompletableFuture<RestStatus> indexDocument(GenericDocument document) {
        final CompletableFuture<RestStatus> future = new CompletableFuture<>();
        final ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);

        executor.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored =
                            this.threadPool.getThreadContext().stashContext()) {
                        IndexRequest indexRequest = createIndexRequest(document);
                        log.info("Previously indexing document {}", document.getId());
                        final RestStatus restStatus = this.client.index(indexRequest).actionGet().status();
                        log.info("POST indexing document {}", document.getId());
                        future.complete(restStatus);
                    } catch (IOException e) {
                        log.error("Error creating IndexRequest due to {}", e.getMessage());
                        future.completeExceptionally(e);
                    }
                });
        return future;
    }

    /**
     * Create an IndexRequest object from a Document object.
     *
     * @param document the document to create the IndexRequest for wazuh-content-manager
     * @return an IndexRequest object
     * @throws IOException thrown by XContentFactory.jsonBuilder()
     */
    private IndexRequest createIndexRequest(GenericDocument document) throws IOException {
        return new IndexRequest()
                .index(INDEX_NAME)
                .source(document.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .id(document.getId())
                .create(true);
    }

    /**
     * Patch a document
     *
     * @param document the document to patch the existing document
     */
    public void patchDocument(JsonObject document) {
        // To do whe we have more definitions
    }
}
