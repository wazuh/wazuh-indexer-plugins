/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager;

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

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.rest.RestPostCommandAction;
import com.wazuh.commandmanager.settings.CommandManagerSettings;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClient;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo;

/**
 * The Command Manager plugin exposes an HTTP API with a single endpoint to receive raw commands
 * from the Wazuh Server. These commands are processed, indexed and sent back to the Server for its
 * delivery to, in most cases, the Agents.
 */
public class CommandManagerPlugin extends Plugin implements ActionPlugin, ReloadablePlugin {
    public static final String COMMAND_MANAGER_BASE_URI = "/_plugins/_command_manager";
    public static final String COMMANDS_URI = COMMAND_MANAGER_BASE_URI + "/commands";
    public static final String COMMAND_MANAGER_INDEX_NAME = ".commands";
    public static final String COMMAND_MANAGER_INDEX_TEMPLATE_NAME = "index-template-commands";

    private CommandIndex commandIndex;
    private CommandManagerSettings commandManagerSettings;

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
        this.commandIndex = new CommandIndex(client, clusterService, threadPool);

        this.commandManagerSettings = CommandManagerSettings.getSettings(environment, null);

        // HttpRestClient stuff
        String uri = "https://httpbin.org/post";
        String payload = "{\"message\": \"Hello world!\"}";
        HttpRestClientDemo.run(uri, payload);
        return Collections.emptyList();
    }

    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster) {
        return Collections.singletonList(new RestPostCommandAction(this.commandIndex));
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
                // Register API settings
                CommandManagerSettings.M_API_USERNAME,
                CommandManagerSettings.M_API_PASSWORD,
                CommandManagerSettings.M_API_URI);
    }

    @Override
    public void reload(Settings settings) {
        // secure settings should be readable
        // final CommandManagerSettings commandManagerSettings =
        // CommandManagerSettings.getClientSettings(secureSettingsPassword);
        // I don't know what I have to do when we want to reload the settings already
        // xxxService.refreshAndClearCache(commandManagerSettings);
    }

    /**
     * Close the resources opened by this plugin.
     *
     * @throws IOException if the plugin failed to close its resources
     */
    @Override
    public void close() throws IOException {
        super.close();
        HttpRestClient.getInstance().stopHttpAsyncClient();
    }
}
