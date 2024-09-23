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
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.shard.IndexingOperationListener;

import java.io.IOException;

public class CommandIndex implements IndexingOperationListener {

    private static final Logger logger = LogManager.getLogger(CommandIndex.class);

    public static Long TIME_OUT_FOR_REQUEST = 15L;
    private final Client client;
    private final ClusterService clusterService;

    /**
     * @param client
     * @param clusterService
     */
    public CommandIndex(
            final Client client,
            final ClusterService clusterService
    ) {
        this.client = client;
        this.clusterService = clusterService;
    }

    /**
     * Check if the CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME index exists.
     *
     * @return whether the index exists.
     */
    public boolean indexExists() {
        return clusterService
                .state()
                .routingTable()
                .hasIndex(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
    }


    public ActionFuture<IndexResponse> create(Command command) {
        try {
            IndexRequest request = new IndexRequest()
                    .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                    .source(command.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .id(command.getId())
                    .create(true);
            return this.client.index(request);
        } catch (IOException e) {
            logger.error("IOException occurred creating command details", e);
        }
        return null;
    }

    /**
     * Persists the command into the commands index
     *
     * @param command  command to persist in the index.
     * @param listener
     */
    protected void create(Command command, ActionListener<String> listener) {
        try {
            // Create index request
            final IndexRequest request = new IndexRequest()
                    .index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                    .source(command.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .id(command.getId())
                    .create(true);

            client.index(request, ActionListener.wrap(response -> {
                listener.onResponse(response.getId());
            }, exception -> {
                if (exception instanceof IOException) {
                    logger.error("IOException occurred creating command details", exception);
                }
                listener.onResponse(null);
            }));
        } catch (IOException e) {
            logger.error("IOException occurred creating command details", e);
            listener.onResponse(null);
        }
    }
}
