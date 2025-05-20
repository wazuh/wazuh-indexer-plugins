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
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.*;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportInterceptor;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;
import org.opensearch.transport.TransportService;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.*;
import java.util.function.Supplier;

import com.wazuh.commandmanager.spi.CommandManagerExtension;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.command.Command;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.SnapshotManager;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin
        implements ClusterPlugin,
                ActionPlugin,
                ReloadablePlugin,
                NetworkPlugin,
                CommandManagerExtension {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private SnapshotManager snapshotManager;
    private ThreadPool threadPool;
    private TransportService transportService;
    private CommandManagerClient commandManagerClient;
    private ClusterService clusterService;
    private Environment environment;

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
        this.environment = environment;
        this.threadPool = threadPool;
        // Initialize the CommandManagerClient.
        this.commandManagerClient = CommandManagerClient.getInstance(client);

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
        log.info("Test mode: {}", PluginSettings.getInstance().getTest_mode());
        if (PluginSettings.getInstance().getTest_mode()) {
            log.info("Dev environment detected, posting test command.");
            this.commandManagerClient.post(Command.create("0"));
        }
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
        return List.of(PluginSettings.CTI_API_URL, PluginSettings.TEST_MODE);
    }

    @Override
    public void reload(Settings settings) throws Exception {}

    @Override
    public List<TransportInterceptor> getTransportInterceptors(
            NamedWriteableRegistry namedWriteableRegistry, ThreadContext threadContext) {
        return List.of(
                new TransportInterceptor() {
                    @Override
                    public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(
                            String action,
                            String executor,
                            boolean forceExecution,
                            TransportRequestHandler<T> actual) {
                        return actual;
                    }
                });
    }

    @Override
    public String getName() {
        return "PEPITO";
    }
}
