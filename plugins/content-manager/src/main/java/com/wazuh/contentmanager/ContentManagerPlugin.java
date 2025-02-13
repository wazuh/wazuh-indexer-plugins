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

import com.wazuh.contentmanager.utils.httpclient.CTIClient;
import com.wazuh.contentmanager.utils.httpclient.CommandManagerClient;
import org.apache.hc.core5.net.URIBuilder;
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
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import com.wazuh.contentmanager.rest.CatalogHandler;
import com.wazuh.contentmanager.rest.ChangesHandler;
import com.wazuh.contentmanager.settings.PluginSettings;

public class ContentManagerPlugin extends Plugin implements ActionPlugin {

    public static String CTI_VD_CONSUMER_URL;
    public static String CTI_CHANGES_URL;
    public static final String CTI_VD_CONSUMER_ENDPOINT = "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";
    public static final String CTI_VD_CHANGES_ENDPOINT = "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes";
    public static CTIClient ctiClient;
    public static CommandManagerClient commandManagerClient;


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
        PluginSettings settings = PluginSettings.getInstance(environment.settings());
        CTI_VD_CONSUMER_URL = URI.create(settings.getCtiBaseUrl() + CTI_VD_CONSUMER_ENDPOINT).toASCIIString();
        CTI_CHANGES_URL = URI.create(settings.getCtiBaseUrl() + CTI_VD_CHANGES_ENDPOINT).toASCIIString();
        ctiClient = CTIClient.getInstance();
        commandManagerClient = CommandManagerClient.getInstance();
        return Collections.emptyList();
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
        return List.of(new CatalogHandler(), new ChangesHandler());
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Collections.singletonList(PluginSettings.CTI_BASE_URL);
    }

    @Override
    public void close() throws IOException {
        super.close();
        // TODO close HttpClient
    }
}
