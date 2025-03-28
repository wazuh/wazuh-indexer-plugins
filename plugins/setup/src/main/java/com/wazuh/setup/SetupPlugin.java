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

import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.UUIDs;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
import org.opensearch.jobscheduler.spi.ScheduledJobParser;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.ReloadablePlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import com.wazuh.setup.index.WazuhIndices;
import com.wazuh.setup.jobscheduler.AgentJobRunner;
import com.wazuh.setup.jobscheduler.JobDocument;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Main class of the Indexer Setup plugin. This plugin is responsible for the creation of the index
 * templates and indices required by Wazuh to work properly.
 */
public class SetupPlugin extends Plugin
        implements ClusterPlugin, ActionPlugin, JobSchedulerExtension, ReloadablePlugin {

    private WazuhIndices indices;
    private JobDocument jobDocument;

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
        PluginSettings.getInstance(environment.settings());

        AgentJobRunner.getInstance().setClient(client).setThreadPool(threadPool);
        this.scheduleAgentJob(client, clusterService, threadPool);
        return List.of(this.indices);
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        this.indices.initialize();
    }

    /**
     * Indexes a document into the jobs index, so that JobScheduler plugin can run it
     *
     * @param client: The cluster client, used for indexing
     * @param clusterService: Provides the addListener method. We use it to determine if this is a new
     *     cluster.
     * @param threadPool: Used by jobDocument to create the document in a thread.
     */
    private void scheduleAgentJob(
            Client client, ClusterService clusterService, ThreadPool threadPool) {
        clusterService.addListener(
                event -> {
                    if (event.localNodeClusterManager() && event.isNewCluster()) {
                        jobDocument = JobDocument.getInstance();
                        CompletableFuture<IndexResponse> indexResponseCompletableFuture =
                                jobDocument.create(
                                        clusterService,
                                        client,
                                        threadPool,
                                        UUIDs.base64UUID(),
                                        getJobType(),
                                        PluginSettings.getInstance().getJobSchedule());
                        indexResponseCompletableFuture.thenAccept(
                                indexResponse -> {
                                    log.info(
                                            "Scheduled task successfully, response: {}",
                                            indexResponse.getResult().toString());
                                });
                    }
                });
    }

    @Override
    public String getJobType() {
        return "";
    }

    @Override
    public String getJobIndex() {
        return "";
    }

    @Override
    public ScheduledJobRunner getJobRunner() {
        return null;
    }

    @Override
    public ScheduledJobParser getJobParser() {
        return null;
    }

    @Override
    public void reload(Settings settings) throws Exception {}
}
