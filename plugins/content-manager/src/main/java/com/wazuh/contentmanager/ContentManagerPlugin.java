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

import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.SnapshotHelper;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin
        implements ClusterPlugin, ActionPlugin, ReloadablePlugin, NetworkPlugin {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private Environment environment;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private TransportService transportService;
    private CommandManagerClient commandManagerClient;

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
        this.contextIndex = new ContextIndex(client);
        this.contentIndex = new ContentIndex(client);
        this.environment = environment;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        // Initialize the CommandManagerClient.
        this.commandManagerClient = CommandManagerClient.getInstance(client);

        return Collections.emptyList();
    }

    /**
     * Call the CTI API on startup and get the latest consumer information into an index
     *
     * @param localNode local Node info
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        String is_dev = System.getenv("IS_DEV");
        log.info("Environment var: {}", is_dev);
        if (is_dev != null) {
            log.info("Dev environment detected, posting test command.");
            this.commandManagerClient.postCommand(Command.create("0"));
        }
        SnapshotHelper snapshotHelper =
                new SnapshotHelper(this.threadPool, this.environment, this.contextIndex, this.contentIndex);
        this.clusterService.addListener(snapshotHelper);
    }

    @Override
    public List<Setting<?>> getSettings() {
        return List.of(PluginSettings.CTI_API_URL);
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
}
