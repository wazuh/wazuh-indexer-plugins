/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.wazuh.setup;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;
import org.wazuh.setup.index.WazuhIndices;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Supplier;


public class WazuhIndexerSetupPlugin extends Plugin implements ClusterPlugin {
    // Implement the relevant Plugin Interfaces here
    private static final Logger log = LogManager.getLogger(WazuhIndexerSetupPlugin.class);

    private WazuhIndices indices;

    @Override
    public Collection<Object> createComponents(
            Client client,
            ClusterService clusterService,
            ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService,
            ScriptService scriptService,
            NamedXContentRegistry xContentRegistry,
            Environment environment,
            NodeEnvironment nodeEnvironment,
            NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<RepositoriesService> repositoriesServiceSupplier
    ) {
        this.indices = new WazuhIndices(client, clusterService);

        return Collections.emptyList();
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {

        try {
            this.indices.putTemplate(new ActionListener<>() {
                @Override
                public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                    log.info("template created");
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("template creation failed");
                }
            });

            this.indices.create(new ActionListener<>() {
                @Override
                public void onResponse(CreateIndexResponse createIndexResponse) {
                    log.info("{} index created", WazuhIndices.INDEX_NAME);
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("error creating index: {}", e.toString());
                }
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        ClusterPlugin.super.onNodeStarted(localNode);
    }
}
