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
package com.wazuh.setup;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import com.wazuh.setup.index.Index;
import com.wazuh.setup.index.IndexStateManagement;
import com.wazuh.setup.index.StateIndex;
import com.wazuh.setup.index.StreamIndex;
import com.wazuh.setup.settings.PluginSettings;
import com.wazuh.setup.utils.JsonUtils;

/**
 * Main class of the Indexer Setup plugin. This plugin is responsible for the creation of the index
 * templates and indices required by Wazuh to work properly.
 */
public class SetupPlugin extends Plugin implements ClusterPlugin {

    private final List<Index> indices = new ArrayList<>();
    // spotless:off
    private final String[] categories = {
        "access-management", // No integration in this category yet
        "applications",
        "cloud-services",
        "cloud-services-aws",
        "cloud-services-azure",
        "cloud-services-gcp",
        "network-activity",
        "security",
        "system-activity",
        "other" // No integration in this category yet
    };
    // spotless:on

    /** Default constructor */
    public SetupPlugin() {}

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
        // spotless:off
        // ISM index
        this.indices.add(new IndexStateManagement(IndexStateManagement.ISM_INDEX_NAME, "templates/ism-config"));
        // Stream indices
        this.indices.add(new StreamIndex("wazuh-alerts-v5", "templates/streams/alerts"));
        this.indices.add(new StreamIndex("wazuh-archives-v5-000001", "templates/streams/archives"));
        // Decoder indices
        for (String category : this.categories) {
            this.indices.add(new StreamIndex(
                "wazuh-events-v5-" + category + "-000001",
                "templates/streams/" + category
            ));
        }

        // State indices
        this.indices.add(new StateIndex("wazuh-states-sca", "templates/states/sca"));
        this.indices.add(new StateIndex("wazuh-states-fim-files", "templates/states/fim-files"));
        this.indices.add(new StateIndex("wazuh-states-fim-registry-keys", "templates/states/fim-registry-keys"));
        this.indices.add(new StateIndex("wazuh-states-fim-registry-values", "templates/states/fim-registry-values"));
        this.indices.add(new StateIndex("wazuh-states-inventory-browser-extensions", "templates/states/inventory-browser-extensions"));
        this.indices.add(new StateIndex("wazuh-states-inventory-groups", "templates/states/inventory-groups"));
        this.indices.add(new StateIndex("wazuh-states-inventory-hardware", "templates/states/inventory-hardware"));
        this.indices.add(new StateIndex("wazuh-states-inventory-hotfixes", "templates/states/inventory-hotfixes"));
        this.indices.add(new StateIndex("wazuh-states-inventory-interfaces", "templates/states/inventory-interfaces"));
        this.indices.add(new StateIndex("wazuh-monitoring", "templates/monitoring"));
        this.indices.add(new StateIndex("wazuh-states-inventory-networks", "templates/states/inventory-networks"));
        this.indices.add(new StateIndex("wazuh-states-inventory-packages", "templates/states/inventory-packages"));
        this.indices.add(new StateIndex("wazuh-states-inventory-ports", "templates/states/inventory-ports"));
        this.indices.add(new StateIndex("wazuh-states-inventory-processes", "templates/states/inventory-processes"));
        this.indices.add(new StateIndex("wazuh-states-inventory-protocols", "templates/states/inventory-protocols"));
        this.indices.add(new StateIndex("wazuh-states-inventory-services", "templates/states/inventory-services"));
        this.indices.add(new StateIndex("wazuh-states-inventory-system", "templates/states/inventory-system"));
        this.indices.add(new StateIndex("wazuh-states-inventory-users", "templates/states/inventory-users"));
        this.indices.add(new StateIndex("wazuh-states-vulnerabilities", "templates/states/vulnerabilities"));
        this.indices.add(new StateIndex("wazuh-statistics", "templates/statistics"));
        // spotless:on

        // Inject dependencies
        JsonUtils utils = new JsonUtils();
        this.indices.forEach(
                index -> {
                    index.setClient(client);
                    index.setClusterService(clusterService);
                    index.setUtils(utils);
                });

        return Collections.emptyList();
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        // Initialize the indices only if this node is the cluster manager node.
        if (localNode.isClusterManagerNode()) {
            this.indices.forEach(Index::initialize);
        }
    }

    @Override
    public List<Setting<?>> getSettings() {
        return List.of(PluginSettings.TIMEOUT, PluginSettings.BACKOFF);
    }
}
