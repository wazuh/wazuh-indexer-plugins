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

import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.rest.CatalogHandler;
import com.wazuh.contentmanager.rest.ChangesHandler;
import com.wazuh.contentmanager.rest.RestPostContentManager;
import com.wazuh.contentmanager.rest.RestPostContextAction;
import com.wazuh.contentmanager.settings.PluginSettings;

public class ContentManagerPlugin extends Plugin implements ClusterPlugin, ActionPlugin {

    public static final String CONTEXT_NAME = "vd_1.0.0";
    public static final String CONSUMER_NAME = "vd_4.8.0";

    private ContextIndex contextIndex;
    private ContentIndex contentIndex;

    /** ClassConstructor * */
    public ContentManagerPlugin() {}

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
        this.contentIndex = new ContentIndex(client, clusterService, threadPool);
        this.contextIndex = new ContextIndex(client, clusterService, threadPool);

        PluginSettings.getInstance(environment.settings(), clusterService);
        return List.of(this.contentIndex, this.contextIndex);
    }

    @Override
    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster) {
        // Just for testing purposes
        return List.of(
                new RestPostContextAction(this.contextIndex),
                new RestPostContentManager(this.contentIndex),
                new CatalogHandler(),
                new ChangesHandler());
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        this.contextIndex.createIndex();
        this.contentIndex.createIndex();
    }

    /**
     * Close the resources opened by this plugin.
     *
     * @throws IOException if the plugin failed to close its resources
     */
    @Override
    public void close() throws IOException {
        super.close();
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Collections.singletonList(PluginSettings.CTI_BASE_URL);
    }
}
