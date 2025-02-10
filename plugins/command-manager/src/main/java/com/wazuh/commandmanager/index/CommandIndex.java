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
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

import com.wazuh.commandmanager.model.Order;
import com.wazuh.commandmanager.settings.PluginSettings;
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
     * Checks if the command index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean indexExists() {
        return this.clusterService.state().routingTable().hasIndex(PluginSettings.getIndexName());
    }

    /**
     * Indexes an array of documents asynchronously.
     *
     * @param orders list of instances of the document model to persist in the index.
     * @return A CompletableFuture with the RestStatus response from the operation
     */
    public CompletableFuture<RestStatus> asyncBulkCreate(ArrayList<Order> orders) {
        final CompletableFuture<RestStatus> future = new CompletableFuture<>();
        final ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);

        final BulkRequest bulkRequest = new BulkRequest();
        for (Order order : orders) {
            log.info("Adding command with id [{}] to the bulk request", order.getId());
            try {
                bulkRequest.add(createIndexRequest(order));
            } catch (IOException e) {
                log.error(
                        "Error creating IndexRequest with document id [{}] due to {}",
                        order.getId(),
                        e.getMessage());
            }
        }

        executor.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored =
                            this.threadPool.getThreadContext().stashContext()) {
                        final String indexTemplateName = PluginSettings.getIndexTemplate();
                        // Create index template if it does not exist.
                        if (IndexTemplateUtils.isMissingIndexTemplate(this.clusterService, indexTemplateName)) {
                            IndexTemplateUtils.putIndexTemplate(this.client, indexTemplateName);
                        } else {
                            log.info("Index template {} already exists. Skipping creation.", indexTemplateName);
                        }

                        final RestStatus restStatus = client.bulk(bulkRequest).actionGet().status();
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
     * @param order the document to create the IndexRequest for COMMAND_MANAGER_INDEX
     * @return an IndexRequest object
     * @throws IOException thrown by XContentFactory.jsonBuilder()
     */
    private IndexRequest createIndexRequest(Order order) throws IOException {
        return new IndexRequest()
                .index(PluginSettings.getIndexName())
                .source(order.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .id(order.getId())
                .create(true);
    }
}
