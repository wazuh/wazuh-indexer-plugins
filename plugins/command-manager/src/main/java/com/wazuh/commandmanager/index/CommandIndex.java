/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.index;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Document;
import com.wazuh.commandmanager.utils.IndexTemplateUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
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
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * Class to manage the Command Manager index and index template.
 */
public class CommandIndex implements IndexingOperationListener {

    private static final Logger logger = LogManager.getLogger(CommandIndex.class);

    private final Client client;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;

    /**
     * Default constructor
     *
     * @param client         OpenSearch client.
     * @param clusterService OpenSearch cluster service.
     * @param threadPool     An OpenSearch ThreadPool.
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
    public CompletableFuture<RestStatus> asyncCreate(Document document) {
        CompletableFuture<RestStatus> future = new CompletableFuture<>();
        ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);

        // Create index template if it does not exist.
        if (!indexTemplateExists(CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME)) {
            putIndexTemplate(CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME);
        } else {
            logger.info(
                    "Index template {} already exists. Skipping creation.",
                    CommandManagerPlugin.COMMAND_MANAGER_INDEX_TEMPLATE_NAME
            );
        }

        logger.debug("Indexing command {}", document);
        try {
            IndexRequest request = new IndexRequest()
                    .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                    .source(document.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .id(document.getId())
                    .create(true);
            executor.submit(
                    () -> {
                        try (ThreadContext.StoredContext ignored = this.threadPool.getThreadContext().stashContext()) {
                            RestStatus restStatus = client.index(request).actionGet().status();
                            future.complete(restStatus);
                        } catch (Exception e) {
                            future.completeExceptionally(e);
                        }
                    }
            );
        } catch (IOException e) {
            logger.error(
                    "Failed to index command with ID {}: {}", document.getId(), e);
        }
        return future;
    }

    /**
     * Checks for the existence of the given index template in the cluster.
     *
     * @param template_name index template name within the resources folder
     * @return whether the index template exists.
     */
    public boolean indexTemplateExists(String template_name) {
        Map<String, IndexTemplateMetadata> templates = this.clusterService
                .state()
                .metadata()
                .templates();
        logger.debug("Existing index templates: {} ", templates);

        return templates.containsKey(template_name);
    }

    /**
     * Inserts an index template
     *
     * @param templateName : The name if the index template to load
     */
    public void putIndexTemplate(String templateName) {
        ExecutorService executor = this.threadPool.executor(ThreadPool.Names.WRITE);
        try {
            // @throws IOException
            Map<String, Object> template = IndexTemplateUtils.fromFile(templateName + ".json");

            PutIndexTemplateRequest putIndexTemplateRequest = new PutIndexTemplateRequest()
                    .mapping(IndexTemplateUtils.get(template, "mappings"))
                    .settings(IndexTemplateUtils.get(template, "settings"))
                    .name(templateName)
                    .patterns((List<String>) template.get("index_patterns"));

            executor.submit(() -> {
                AcknowledgedResponse acknowledgedResponse = this.client
                        .admin()
                        .indices()
                        .putTemplate(putIndexTemplateRequest)
                        .actionGet();
                if (acknowledgedResponse.isAcknowledged()) {
                    logger.info(
                            "Index template created successfully: {}",
                            templateName
                    );
                }
            });

        } catch (IOException e) {
            logger.error("Error reading index template from filesystem {}", templateName);
        }
    }
}
