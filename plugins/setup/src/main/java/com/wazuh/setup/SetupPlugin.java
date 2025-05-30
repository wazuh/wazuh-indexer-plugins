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

import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.indexmanagement.spi.IndexManagementExtension;
import org.opensearch.indexmanagement.spi.indexstatemanagement.ActionParser;
import org.opensearch.indexmanagement.spi.indexstatemanagement.IndexMetadataService;
import org.opensearch.indexmanagement.spi.indexstatemanagement.StatusChecker;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

import com.wazuh.setup.index.PolicyIndex;
import com.wazuh.setup.index.WazuhIndices;

/**
 * Main class of the Indexer Setup plugin. This plugin is responsible for the creation of the index
 * templates and indices required by Wazuh to work properly.
 */
public class SetupPlugin extends Plugin implements ClusterPlugin, IndexManagementExtension {

    private static final Logger log = LogManager.getLogger(SetupPlugin.class);

    // private static final CountDownLatch onNodeStartedLatch = new CountDownLatch(1);
    private WazuhIndices indices;
    private PolicyIndex policyIndex;
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
        this.indices = new WazuhIndices(client, clusterService);
        this.policyIndex = new PolicyIndex(client, clusterService);
        return List.of(this.indices);
    }

    /// **
    // * Mostly meant for integration test cases. Will wait for the onNodeStarted() method to be
    // * executed until the timeout
    // *
    // * @param timeout Time to wait
    // * @param unit Unit of the timeout
    // * @return boolean representing the status
    // */
    // public boolean waitUntilNodeStarted(long timeout, TimeUnit unit)
    //        throws InterruptedException {
    //    // if (!onNodeStartedLatch.await(timeout, unit)) {
    //    //    throw new IllegalStateException("Setup plugin node startup logic did not complete in
    //    // time");
    //    // }
    //    return onNodeStartedLatch.await(timeout, unit);
    // }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        this.indices.initialize();
        this.policyIndex.putISMTemplate();
        // testIndex();
        // this.policyIndex.indexPolicy();
        // onNodeStartedLatch.countDown();
    }

    private void testIndex() {
        this.client.index(
                new IndexRequest().index("test").id("1").source("{\"field\":\"value\"}"),
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        log.info("created");
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("not created");
                    }
                });
    }

    @Override
    public String getExtensionName() {
        return "";
    }

    @Override
    public List<ActionParser> getISMActionParsers() {
        return List.of();
    }

    @Override
    public StatusChecker statusChecker() {
        return null;
    }

    @Override
    public Map<String, IndexMetadataService> getIndexMetadataService() {
        return Map.of();
    }

    @Override
    public String overrideClusterStateIndexUuidSetting() {
        return "";
    }
}
