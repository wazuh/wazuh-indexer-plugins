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
package com.wazuh.commandmanager.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexTemplateMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Document;
import com.wazuh.commandmanager.utils.IndexTemplateUtils;

/** Class to manage the Command Manager index and index template. */
public class CommandIndex implements IndexingOperationListener {

    private static final Logger log = LogManager.getLogger(CommandIndex.class);

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
    public CommandIndex(Client client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    /**
     * @param document instance of the document model to persist in the index.
     * @return A CompletableFuture with the RestStatus response from the operation
     */
    @Deprecated
    public CompletableFuture<RestStatus> asyncCreate(Document document) {
        CompletableFuture<RestStatus> future = new CompletableFuture<>();
        ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);

        log.info("Indexing command with id [{}]", document.getId());
        try {
            IndexRequest request = createIndexRequest(document);
            executor.submit(
                    () -> {
                        try (ThreadContext.StoredContext ignored =
                                this.threadPool.getThreadContext().stashContext()) {
                            // Create index template if it does not exist.
                            if (!IndexTemplateUtils.indexTemplateExists(
                                    this.clusterService,
                                    CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME)) {
                                IndexTemplateUtils.putIndexTemplate(
                                        this.client,
                                        CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME);
                            } else {
                                log.info(
                                        "Index template {} already exists. Skipping creation.",
                                        CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME);
                            }

                            RestStatus restStatus = client.index(request).actionGet().status();
                            future.complete(restStatus);
                        } catch (Exception e) {
                            log.error(
                                    "Error indexing command with id [{}] due to {}",
                                    document.getId(),
                                    e.getMessage());
                            future.completeExceptionally(e);
                        }
                    });
        } catch (IOException e) {
            log.error("Error indexing command with id [{}] due to {}", document.getId(), e);
        }
        return future;
    }

    /**
     * @param documents list of instances of the document model to persist in the index.
     * @return A CompletableFuture with the RestStatus response from the operation
     */
    public CompletableFuture<RestStatus> asyncBulkCreate(ArrayList<Document> documents) {
        CompletableFuture<RestStatus> future = new CompletableFuture<>();
        ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);

        BulkRequest bulkRequest = new BulkRequest();
        for (Document document : documents) {
            log.info("Adding command with id [{}] to the bulk request", document.getId());
            try {
                bulkRequest.add(createIndexRequest(document));
            } catch (IOException e) {
                log.error(
                        "Error creating IndexRequest with document id [{}] due to {}",
                        document.getId(),
                        e);
            }
        }

        executor.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored =
                            this.threadPool.getThreadContext().stashContext()) {
                        // Create index template if it does not exist.
                        if (!IndexTemplateUtils.indexTemplateExists(
                                this.clusterService,
                                CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME)) {
                            IndexTemplateUtils.putIndexTemplate(
                                    this.client,
                                    CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME);
                        } else {
                            log.info(
                                    "Index template {} already exists. Skipping creation.",
                                    CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME);
                        }

                        RestStatus restStatus = client.bulk(bulkRequest).actionGet().status();
                        future.complete(restStatus);
                    } catch (Exception e) {
                        log.error("Error indexing commands with bulk due to {}", e.getMessage());
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
    private IndexRequest createIndexRequest(Document document) throws IOException {
        IndexRequest request =
                new IndexRequest()
                        .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                        .source(
                                document.toXContent(
                                        XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .id(document.getId())
                        .create(true);
        return request;
    }
}
