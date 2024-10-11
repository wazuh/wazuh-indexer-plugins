/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager;

import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.rest.action.RestPostCommandAction;
import com.wazuh.commandmanager.settings.CommandManagerSettings;
import com.wazuh.commandmanager.settings.PluginSettings;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.ReloadablePlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.Arrays;
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
public class CommandManagerPlugin extends Plugin implements ActionPlugin, ReloadablePlugin {
    public static final String COMMAND_MANAGER_BASE_URI = "/_plugins/_commandmanager";
    public static final String COMMAND_MANAGER_INDEX_NAME = ".commands";
    public static final String COMMAND_MANAGER_INDEX_TEMPLATE_NAME = "index-template-commands";

    private CommandIndex commandIndex;
    private PluginSettings pluginSettings;

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
        this.pluginSettings = PluginSettings.getPluginSettingsInstance();
        pluginSettings.setEnv(environment);
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

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
                // Register EC2 discovery settings: discovery.ec2
                CommandManagerSettings.ACCESS_KEY_SETTING,
                CommandManagerSettings.SECRET_KEY_SETTING,
                CommandManagerSettings.SESSION_TOKEN_SETTING,
                CommandManagerSettings.PROXY_HOST_SETTING,
                CommandManagerSettings.PROXY_PORT_SETTING
        );
    }

    @Override
    public void reload(Settings settings) {
        // secure settings should be readable
        final CommandManagerSettings commandManagerSettings = CommandManagerSettings.getClientSettings(settings);
        //I don't know what I have to do when we want to reload the settings already
        //ec2Service.refreshAndClearCache(commandManagerSettings);
    }
}
