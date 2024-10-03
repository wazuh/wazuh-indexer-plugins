/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager;

import com.wazuh.commandmanager.config.reader.ConfigReader;
import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.rest.action.RestPostCommandAction;
import com.wazuh.commandmanager.scheduler.JobScheduler;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

/**
 * The Command Manager plugin exposes an HTTP API with a single endpoint to
 * receive raw commands from the Wazuh Server. These commands are processed,
 * indexed and sent back to the Server for its delivery to, in most cases, the
 * Agents.
 */
public class CommandManagerPlugin extends Plugin implements ActionPlugin {
    public static final String COMMAND_MANAGER_BASE_URI = "/_plugins/_commandmanager";
    public static final String COMMAND_MANAGER_INDEX_NAME = ".commands";
    public static final String COMMAND_MANAGER_INDEX_TEMPLATE_NAME = "index-template-commands";

    private CommandIndex commandIndex;

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
        this.commandIndex = new CommandIndex(client, clusterService, threadPool);
        ConfigReader configReader = new ConfigReader("127.0.0.1", 8080, "", "admin", "admin");
        JobScheduler jobScheduler = new JobScheduler(threadPool, configReader);
        return Collections.emptyList();
    }

    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster
    ) {
        return Collections.singletonList(new RestPostCommandAction(this.commandIndex));
    }
}
