/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
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
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.common.unit.TimeValue;
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
import com.wazuh.commandmanager.utils.httpclient.HttpRestClient;

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
        implements ActionPlugin, ReloadablePlugin, JobSchedulerExtension {
    public static final String COMMAND_MANAGER_BASE_URI = "/_plugins/_command_manager";
    public static final String COMMANDS_URI = COMMAND_MANAGER_BASE_URI + "/commands";
    public static final String COMMAND_MANAGER_INDEX_NAME = ".commands";
    public static final String COMMAND_MANAGER_INDEX_TEMPLATE_NAME = "index-template-commands";
    public static final String JOB_INDEX_NAME = ".scheduled-commands";
    public static final Integer JOB_PERIOD_MINUTES = 1;
    public static final Integer PAGE_SIZE = 2;
    public static final Long DEFAULT_TIMEOUT_SECONDS = 20L;
    public static final TimeValue PIT_KEEPALIVE_SECONDS = TimeValue.timeValueSeconds(30L);

    private static final Logger log = LogManager.getLogger(CommandManagerPlugin.class);

    private CommandIndex commandIndex;
    private JobDocument jobDocument;

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

        // JobSchedulerExtension stuff
        CommandManagerJobRunner.getInstance()
            .setThreadPool(threadPool)
            .setClient(client)
            .setClusterService(clusterService);

        scheduleCommandJob(client, clusterService, threadPool);

        // HttpRestClient stuff
        // String uri = "https://httpbin.org/post";
        // String payload = "{\"message\": \"Hello world!\"}";
        // HttpRestClientDemo.run(uri, payload);

        return Collections.emptyList();
    }

    private void scheduleCommandJob(
            Client client, ClusterService clusterService, ThreadPool threadPool) {
        clusterService.addListener(
                event -> {
                    if (event.localNodeClusterManager() && event.isNewCluster()) {
                        jobDocument = JobDocument.getInstance();
                        CompletableFuture<IndexResponse> indexResponseCompletableFuture =
                                jobDocument.create(
                                        client,
                                        threadPool,
                                        UUIDs.base64UUID(),
                                        getJobType(),
                                        JOB_PERIOD_MINUTES);
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
        return Arrays.asList(
                // Register API settings
                PluginSettings.M_API_AUTH_USERNAME,
                PluginSettings.M_API_AUTH_PASSWORD,
                PluginSettings.M_API_URI);
    }

    @Override
    public void reload(Settings settings) {
        // secure settings should be readable
        // final PluginSettings commandManagerSettings =
        // PluginSettings.getClientSettings(secureSettingsPassword);
        // I don't know what I have to do when we want to reload the settings already
        // xxxService.refreshAndClearCache(commandManagerSettings);
    }

    @Override
    public String getJobType() {
        return "command_manager_scheduler_extension";
    }

    @Override
    public String getJobIndex() {
        return JOB_INDEX_NAME;
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
