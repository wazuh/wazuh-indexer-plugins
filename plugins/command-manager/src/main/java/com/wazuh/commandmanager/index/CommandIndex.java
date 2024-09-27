/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.index;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;

public class CommandIndex implements IndexingOperationListener {

    private static final Logger logger = LogManager.getLogger(CommandIndex.class);

    private final Client client;

    /**
     * @param client
     */
    public CommandIndex(Client client) {
        this.client = client;
    }

    /**
     * @param command    a Command class command
     * @param threadPool
     * @return Indexing operation RestStatus response
     * @throws ExecutionException
     */
    public RestStatus create(Command command, ThreadPool threadPool) throws ExecutionException, InterruptedException {
        CompletableFuture<IndexResponse> inProgressFuture = new CompletableFuture<>();
        try {
            logger.info("Creating request for command: {}", command.getId());
            IndexRequest request = new IndexRequest()
                    .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                    .source(command.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .id(command.getId())
                    .create(true);

            client.index(
                    request,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexResponse indexResponse) {
                            inProgressFuture.complete(indexResponse);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            logger.info("Could not process command: {}", command.getId(), e);
                            inProgressFuture.completeExceptionally(e);
                        }
                    }
            );
        } catch (IOException e) {
            logger.error("IOException occurred creating command details", e);
        }
        return inProgressFuture.get().status();
    }

    /**
     *
     * @param command: A Command model object
     * @param threadPool: An OpenSearch ThreadPool as passed to the createComponents() method
     * @return A CompletableFuture with the RestStatus response from the operation
     */

    public CompletableFuture<RestStatus> asyncCreate(Command command, ThreadPool threadPool)  {
        CompletableFuture<RestStatus> future = new CompletableFuture<>();
        ExecutorService executor = threadPool.executor(ThreadPool.Names.WRITE);
        try {
            IndexRequest request = new IndexRequest()
                .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                .source(command.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .id(command.getId())
                .create(true);
            executor.submit(
                () -> {
                    try (ThreadContext.StoredContext ignored = threadPool.getThreadContext().stashContext()) {
                        RestStatus restStatus = client.index(request).actionGet().status();
                        future.complete(restStatus);
                    } catch (Exception e) {
                        future.completeExceptionally(e);
                    }
                }
            );
        } catch (Exception e) {
            logger.error(e);
        }
        return future;
    }

}
