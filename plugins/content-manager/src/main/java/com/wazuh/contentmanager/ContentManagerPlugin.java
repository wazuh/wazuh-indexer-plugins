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
package com.wazuh.contentmanager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.transport.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
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

import java.util.*;
import java.util.function.Supplier;

import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.SnapshotManager;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin implements ClusterPlugin {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private SnapshotManager snapshotManager;
    private ThreadPool threadPool;
    private ClusterService clusterService;

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
            Supplier<RepositoriesService> repositoriesServiceSupplier) {
        PluginSettings.getInstance(environment.settings(), clusterService);
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.contextIndex = new ContextIndex(client);
        this.contentIndex = new ContentIndex(client);
        this.snapshotManager =
                new SnapshotManager(environment, this.contextIndex, this.contentIndex, new Privileged());
        return Collections.emptyList();
    }

    /**
     * The initialization requires the existence of the {@link ContentIndex#INDEX_NAME} index. For
     * this reason, we use a ClusterStateListener to listen for the creation of this index by the
     * "setup" plugin, to then proceed with the initialization.
     *
     * @param localNode local Node info
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        // Only cluster managers are responsible for the initialization.
        if (localNode.isClusterManagerNode()) {
            if (this.clusterService.state().routingTable().hasIndex(ContentIndex.INDEX_NAME)) {
                this.start();
            }

            // To be removed once we include the Job Scheduler.
            this.clusterService.addListener(
                    event -> {
                        if (event.indicesCreated().contains(ContentIndex.INDEX_NAME)) {
                            this.start();
                        }
                    });
        }
    }

    /**
     * Initialize. The initialization consists of:
     *
     * <pre>
     *     1. fetching the latest consumer's information from the CTI API.
     *     2. initialize from a snapshot if the local consumer does not exist, or its offset is 0.
     * </pre>
     */
    private void start() {
        try {
            this.threadPool
                    .generic()
                    .execute(
                            () -> {
                                this.contextIndex.createIndex();
                                this.snapshotManager.initialize();
                            });
        } catch (Exception e) {
            // Log or handle exception
            log.error("Error initializing snapshot helper: {}", e.getMessage(), e);
        }
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
                PluginSettings.INDEXER_USERNAME,
                PluginSettings.INDEXER_PASSWORD,
                PluginSettings.CONSUMER_ID,
                PluginSettings.CONTEXT_ID,
                PluginSettings.CLIENT_TIMEOUT,
                PluginSettings.CTI_API_URL,
                PluginSettings.CTI_CLIENT_MAX_ATTEMPTS,
                PluginSettings.CTI_CLIENT_SLEEP_TIME,
                PluginSettings.JOB_MAX_DOCS,
                PluginSettings.JOB_SCHEDULE,
                PluginSettings.MAX_CHANGES,
                PluginSettings.MAX_CONCURRENT_BULKS,
                PluginSettings.MAX_ITEMS_PER_BULK);
    }
}
