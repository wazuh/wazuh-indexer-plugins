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
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.util.Privileged;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin implements ClusterPlugin, ActionPlugin {

    private ContextIndex contextIndex;

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
        return Collections.emptyList();
    }

    /**
     * Call the CTI API on startup and get the latest consumer information into an index
     *
     * @param localNode local Node info
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        ConsumerInfo consumerInfo =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());
        this.contextIndex.index(consumerInfo);

        // Wrapping up for testing
        //        Privileged.doPrivilegedRequest(
        //                () -> {
        //                    CTIClient.getInstance()
        //                            .download(
        //
        // "https://cti.wazuh.com/store/contexts/vd_1.0.0/consumers/vd_4.8.0/1432540_1741603172.zip",
        //                                    environment);
        //                    String snapshotZip =
        //
        // this.environment.resolveRepoFile("1432540_1741603172.zip").toString();
        //                    String snapshot =
        //                            this.environment
        //
        // .resolveRepoFile("vd_1.0.0_vd_4.8.0_1432540_1741603172.json")
        //                                    .toString();
        //                    String dir = this.environment.resolveRepoFile("").toString();
        //                    try {
        //                        Unzip.unzip(snapshotZip, dir, this.environment);
        //                    } catch (IOException e) {
        //                        throw new RuntimeException(e);
        //                    }
        //                    this.contentIndex.fromSnapshot(snapshot);
        //                    return null;
        //                });
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Collections.singletonList(PluginSettings.CTI_API_URL);
    }
}
