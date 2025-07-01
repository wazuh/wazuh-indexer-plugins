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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.opensearch.action.admin.cluster.settings.ClusterUpdateSettingsResponse;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
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

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import com.wazuh.setup.index.Index;
import com.wazuh.setup.index.IndexStateManagement;
import com.wazuh.setup.index.StateIndex;
import com.wazuh.setup.index.StreamIndex;
import com.wazuh.setup.utils.IndexUtils;

/**
 * Main class of the Indexer Setup plugin. This plugin is responsible for the creation of the index
 * templates and indices required by Wazuh to work properly.
 */
public class SetupPlugin extends Plugin implements ClusterPlugin {

    private static final Logger log = LogManager.getLogger(SetupPlugin.class);
    public static final TimeValue TIMEOUT = new TimeValue(30L, TimeUnit.SECONDS);
    private final List<Index> indices = new ArrayList<>();
    private Client client;

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
        this.indices.add(new IndexStateManagement(".opendistro-ism-config", "opendistro-ism-config"));
        // Stream indices
        this.indices.add(new StreamIndex("wazuh-alerts-5.x-000001", "index-template-alerts", "wazuh-alerts"));
        this.indices.add(new StreamIndex("wazuh-archives-5.x-000001", "index-template-archives", "wazuh-archives"));
        // State indices
        this.indices.add(new StateIndex("wazuh-states-sca", "index-template-sca"));
        this.indices.add(new StateIndex("wazuh-states-fim-files", "index-template-fim-files"));
        this.indices.add(new StateIndex("wazuh-states-fim-registry-keys", "index-template-fim-registry-keys"));
        this.indices.add(new StateIndex("wazuh-states-fim-registry-values", "index-template-fim-registry-values"));
        this.indices.add(new StateIndex("wazuh-states-inventory-groups", "index-template-groups"));
        this.indices.add(new StateIndex("wazuh-states-inventory-hardware", "index-template-hardware"));
        this.indices.add(new StateIndex("wazuh-states-inventory-hotfixes", "index-template-hotfixes"));
        this.indices.add(new StateIndex("wazuh-states-inventory-interfaces", "index-template-interfaces"));
        this.indices.add(new StateIndex("wazuh-monitoring", "index-template-monitoring"));
        this.indices.add(new StateIndex("wazuh-states-inventory-networks", "index-template-networks"));
        this.indices.add(new StateIndex("wazuh-states-inventory-packages", "index-template-packages"));
        this.indices.add(new StateIndex("wazuh-states-inventory-ports", "index-template-ports"));
        this.indices.add(new StateIndex("wazuh-states-inventory-processes", "index-template-processes"));
        this.indices.add(new StateIndex("wazuh-states-inventory-protocols", "index-template-protocols"));
        this.indices.add(new StateIndex("wazuh-states-inventory-system", "index-template-system"));
        this.indices.add(new StateIndex("wazuh-states-inventory-users", "index-template-users"));
        this.indices.add(new StateIndex("wazuh-states-vulnerabilities", "index-template-vulnerabilities"));
        this.indices.add(new StateIndex("wazuh-statistics", "index-template-statistics"));
        // spotless:on

        // Inject dependencies
        IndexUtils utils = new IndexUtils();
        this.indices.forEach(
                index -> {
                    index.setClient(client);
                    index.setClusterService(clusterService);
                    index.setIndexUtils(utils);
                });

        this.client = client;
        return Collections.emptyList();
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        // Initialize the indices only if this node is the cluster manager node.
        if (localNode.isClusterManagerNode()) {
            Map<String, Boolean> initializationResult = new HashMap<>();
            this.indices.forEach(
                    index -> {
                        initializationResult.put(index.getIndex(), index.initialize());
                    });

            // A block is acquired. If the indices have been initialized correctly, the block is released;
            // otherwise, the block remains held.
            this.setBlock(true);
            log.info("Performing index verification process");
            if (!initializationResult.containsValue(false)) {
                this.setBlock(false);
            }
        }
    }

    /**
     * Sets the read-only and allow-delete block mode on the Wazuh-indexer cluster.
     *
     * <p>This method updates the cluster configuration to enable or disable read-only and delete
     * permissions across all nodes, depending on the value of {@code mode}. When {@code mode} is
     * {@code true}, it activates the read-only and allow-delete block. When {@code mode} is {@code
     * false}, it deactivates the block.
     *
     * @param mode {@code true} to enable read-only and allow-delete block, {@code false} to disable
     *     it.
     */
    public void setBlock(boolean mode) {
        ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        if (mode) {
            request.persistentSettings(
                    Settings.builder().put("cluster.blocks.read_only_allow_delete", true).build());
        } else {
            // To deactivate the block is necessary to use putNull method instead of changing the block to
            // false,
            // this is because if we only change the block to false in it leaves some extra metadata
            request.persistentSettings(
                    Settings.builder().putNull("cluster.blocks.read_only_allow_delete").build());
        }

        this.client
                .admin()
                .cluster()
                .updateSettings(
                        request,
                        new ActionListener<>() {

                            @Override
                            public void onResponse(ClusterUpdateSettingsResponse response) {
                                if (mode) {
                                    log.info("Read only and allow delete block enabled: {}", response);
                                } else {
                                    log.info("Read only and allow delete block disabled: {}", response);
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error("Failed to add read only and allow block", e);
                            }
                        });
    }
}
