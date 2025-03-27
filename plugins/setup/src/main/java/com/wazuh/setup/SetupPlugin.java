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
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.UUIDs;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
import org.opensearch.jobscheduler.spi.ScheduledJobParser;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.ReloadablePlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import com.wazuh.setup.index.WazuhIndices;
import com.wazuh.setup.jobscheduler.AgentJobParameter;
import com.wazuh.setup.jobscheduler.AgentJobRunner;
import com.wazuh.setup.jobscheduler.JobDocument;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Main class of the Indexer Setup plugin. This plugin is responsible for the creation of the index
 * templates and indices required by Wazuh to work properly.
 */
public class SetupPlugin extends Plugin
        implements ClusterPlugin, ActionPlugin, JobSchedulerExtension, ReloadablePlugin {

    private static final Logger log = LogManager.getLogger(SetupPlugin.class);

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

        AgentJobRunner.getInstance()
                .setClient(client)
                .setThreadPool(threadPool)
                .setClusterService(clusterService);

        this.scheduleAgentStatusJob(client, clusterService, threadPool);

        return List.of(this.indices);
    }

    /**
     * Indexes a document into the jobs index, so that JobScheduler plugin can run it
     *
     * @param client: The cluster client, used for indexing
     * @param clusterService: Provides the addListener method. We use it to determine if this is a new
     *     cluster.
     * @param threadPool: Used by jobDocument to create the document in a thread.
     */
    private void scheduleAgentStatusJob(
            Client client, ClusterService clusterService, ThreadPool threadPool) {
        log.info("Checking if this is a new cluster");
        clusterService.addListener(
                event -> {
                    if (event.localNodeClusterManager() && event.isNewCluster()) {
                        log.info("This is a new cluster {}", clusterService.toString());
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
                    } else {
                        log.info("Not a new cluster {}", clusterService.toString());
                    }
                });
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
                // Register API settings
                PluginSettings.CLIENT_TIMEOUT, PluginSettings.MAX_DOCS, PluginSettings.JOB_SCHEDULE);
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        this.indices.initialize();
    }

    @Override
    public String getJobType() {
        log.info("JobType " + PluginSettings.getJobType() + " executed ");
        return PluginSettings.getJobType();
    }

    @Override
    public String getJobIndex() {
        log.info("JobIndex " + PluginSettings.getJobIndexName() + " executed ");
        return PluginSettings.getJobIndexName();
    }

    @Override
    public ScheduledJobRunner getJobRunner() {
        log.info("getJobRunner() executed");
        return AgentJobRunner.getInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
        log.info("getJobParser() executed");
        return (parser, id, jobDocVersion) -> {
            AgentJobParameter jobParameter = new AgentJobParameter();
            XContentParserUtils.ensureExpectedToken(
                    XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

            while (!parser.nextToken().equals(XContentParser.Token.END_OBJECT)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case AgentJobParameter.NAME_FIELD:
                        jobParameter.setJobName(parser.text());
                        break;
                    case AgentJobParameter.ENABLED_FIELD:
                        jobParameter.setEnabled(parser.booleanValue());
                        break;
                    case AgentJobParameter.ENABLED_TIME_FIELD:
                        jobParameter.setEnabledTime(parseInstantValue(parser));
                        break;
                    case AgentJobParameter.LAST_UPDATE_TIME_FIELD:
                        jobParameter.setLastUpdateTime(parseInstantValue(parser));
                        break;
                    case AgentJobParameter.SCHEDULE_FIELD:
                        jobParameter.setSchedule(ScheduleParser.parse(parser));
                        break;
                    default:
                        XContentParserUtils.throwUnknownToken(parser.currentToken(), parser.getTokenLocation());
                }
            }
            return jobParameter;
        };
    }

    /**
     * Returns the proper Instant object with milliseconds from the Unix epoch when the current token
     * actually holds a value.
     *
     * @param parser: The parser as provided by JobScheduler
     */
    private Instant parseInstantValue(XContentParser parser) throws IOException {
        if (XContentParser.Token.VALUE_NULL.equals(parser.currentToken())) {
            return null;
        }
        if (parser.currentToken().isValue()) {
            return Instant.ofEpochMilli(parser.longValue());
        }
        XContentParserUtils.throwUnknownToken(parser.currentToken(), parser.getTokenLocation());
        return null;
    }

    @Override
    public void reload(Settings settings) {
        // TODO
    }
}
