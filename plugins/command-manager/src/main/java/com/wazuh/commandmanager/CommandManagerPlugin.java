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
package com.wazuh.commandmanager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.UUIDs;
import org.opensearch.common.settings.*;
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
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.ReloadablePlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.*;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.jobscheduler.CommandManagerJobParameter;
import com.wazuh.commandmanager.jobscheduler.CommandManagerJobRunner;
import com.wazuh.commandmanager.jobscheduler.JobDocument;
import com.wazuh.commandmanager.rest.RestPostCommandAction;
import com.wazuh.commandmanager.settings.PluginSettings;

/**
 * The Command Manager plugin exposes an HTTP API with a single endpoint to receive raw commands
 * from the Wazuh Server. These commands are processed, indexed and sent back to the Server for its
 * delivery to, in most cases, the Agents. The Command Manager plugin exposes an HTTP API with a
 * single endpoint to receive raw commands from the Wazuh Server. These commands are processed,
 * indexed and sent back to the Server for its delivery to, in most cases, the Agents.
 *
 * <p>The Command Manager plugin is also a JobScheduler extension plugin.
 */
public class CommandManagerPlugin extends Plugin
        implements ActionPlugin, JobSchedulerExtension, ReloadablePlugin {
    public static final String COMMAND_DOCUMENT_PARENT_OBJECT_NAME = "command";
    public static final String JOB_TYPE = "command_manager_scheduler_extension";
    public static final String JOB_INDEX = ".scheduled-commands";

    private static final Logger log = LogManager.getLogger(CommandManagerPlugin.class);

    private CommandIndex commandIndex;
    private JobDocument jobDocument;
    private PluginSettings settings;

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
        // Command index repository initialization.
        this.commandIndex = new CommandIndex(client, clusterService, threadPool);
        this.settings = PluginSettings.getInstance(environment.settings());

        // Scheduled job initialization
        // NOTE it's very likely that client and thread pool may not be required as the command
        // index
        // repository already use them. All queries to the index should be under this class.
        log.info("[SETTINGS] Plugin Settings loaded.");
        CommandManagerJobRunner.getInstance()
                .setClient(client)
                .setThreadPool(threadPool)
                .setIndexRepository(this.commandIndex);
        this.scheduleCommandJob(client, clusterService, threadPool);

        return Collections.emptyList();
    }

    /**
     * Indexes a document into the jobs index, so that JobScheduler plugin can run it
     *
     * @param client: The cluster client, used for indexing
     * @param clusterService: Provides the addListener method. We use it to determine if this is a
     *     new cluster.
     * @param threadPool: Used by jobDocument to create the document in a thread.
     */
    private void scheduleCommandJob(
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
                                        settings.getJobSchedule());
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
        log.info("[SETTINGS] Retrieving settings.");
        return Arrays.asList(
                // Register API settings
                PluginSettings.TIMEOUT,
                PluginSettings.JOB_PAGE_SIZE,
                PluginSettings.JOB_SCHEDULE,
                PluginSettings.JOB_KEEP_ALIVE,
                PluginSettings.JOB_INDEX_TEMPLATE,
                PluginSettings.API_PREFIX,
                PluginSettings.API_ENDPOINT,
                PluginSettings.INDEX_NAME,
                PluginSettings.INDEX_TEMPLATE);
    }

    @Override
    public String getJobType() {
        return CommandManagerPlugin.JOB_TYPE;
    }

    @Override
    public String getJobIndex() {
        return CommandManagerPlugin.JOB_INDEX;
    }

    @Override
    public ScheduledJobRunner getJobRunner() {
        log.info("getJobRunner() executed");
        return CommandManagerJobRunner.getInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
        log.info("getJobParser() executed");
        return (parser, id, jobDocVersion) -> {
            CommandManagerJobParameter jobParameter = new CommandManagerJobParameter();
            XContentParserUtils.ensureExpectedToken(
                    XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

            while (!parser.nextToken().equals(XContentParser.Token.END_OBJECT)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case CommandManagerJobParameter.NAME_FIELD:
                        jobParameter.setJobName(parser.text());
                        break;
                    case CommandManagerJobParameter.ENABLED_FIELD:
                        jobParameter.setEnabled(parser.booleanValue());
                        break;
                    case CommandManagerJobParameter.ENABLED_TIME_FIELD:
                        jobParameter.setEnabledTime(parseInstantValue(parser));
                        break;
                    case CommandManagerJobParameter.LAST_UPDATE_TIME_FIELD:
                        jobParameter.setLastUpdateTime(parseInstantValue(parser));
                        break;
                    case CommandManagerJobParameter.SCHEDULE_FIELD:
                        jobParameter.setSchedule(ScheduleParser.parse(parser));
                        break;
                    default:
                        XContentParserUtils.throwUnknownToken(
                                parser.currentToken(), parser.getTokenLocation());
                }
            }
            return jobParameter;
        };
    }

    /**
     * Returns the proper Instant object with milliseconds from the Unix epoch when the current
     * token actually holds a value.
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
