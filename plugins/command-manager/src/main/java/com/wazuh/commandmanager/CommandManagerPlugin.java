/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager;


import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.jobscheduler.CommandManagerJobParameter;
import com.wazuh.commandmanager.jobscheduler.CommandManagerJobRunner;
import com.wazuh.commandmanager.jobscheduler.JobDocument;
import com.wazuh.commandmanager.rest.action.RestPostCommandAction;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClient;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.UUIDs;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
import org.opensearch.jobscheduler.spi.ScheduledJobParser;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.*;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.function.Supplier;

/**
 * The Command Manager plugin exposes an HTTP API with a single endpoint to
 * receive raw commands from the Wazuh Server. These commands are processed,
 * indexed and sent back to the Server for its delivery to, in most cases, the
 * Agents.
 * <p>
 * The Command Manager plugin is also a JobScheduler extension plugin.
 */
public class CommandManagerPlugin extends Plugin implements ActionPlugin, JobSchedulerExtension {
    public static final String COMMAND_MANAGER_BASE_URI = "/_plugins/_commandmanager";
    public static final String COMMAND_MANAGER_SCHEDULER_URI = COMMAND_MANAGER_BASE_URI + "/schedule";
    public static final String COMMAND_MANAGER_INDEX_NAME = ".commands";
    public static final String COMMAND_MANAGER_INDEX_TEMPLATE_NAME = "index-template-commands";
    public static final String JOB_INDEX_NAME = ".scheduled-commands";
    public static final Integer JOB_PERIOD_MINUTES = 1;

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
        Supplier<RepositoriesService> repositoriesServiceSupplier
    ) {
        this.commandIndex = new CommandIndex(client, clusterService, threadPool);

        // JobSchedulerExtension stuff
        CommandManagerJobRunner jobRunner = CommandManagerJobRunner.getJobRunnerInstance();
        jobRunner.setThreadPool(threadPool);

        clusterService.addListener(event -> {
            if(event.localNodeClusterManager() && event.isNewCluster()) {
                jobDocument = JobDocument.getInstance();
                CompletableFuture<IndexResponse> indexResponseCompletableFuture = jobDocument.create(client, threadPool, UUIDs.base64UUID(), getJobType(), JOB_PERIOD_MINUTES);
                indexResponseCompletableFuture.thenAccept(
                    indexResponse -> {
                        log.info("Scheduled task successfully, response: {}", indexResponse.getResult().toString());
                    }
                );
            }
        });

        // HttpRestClient stuff
        String uri = "https://httpbin.org/post";
        String payload = "{\"message\": \"Hello world!\"}";
        HttpRestClientDemo.run(uri, payload);

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
        Supplier<DiscoveryNodes> nodesInCluster
    ) {
        return Collections.singletonList(new RestPostCommandAction(this.commandIndex));
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
        return CommandManagerJobRunner.getJobRunnerInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
        log.info("getJobParser() executed");
        return (parser, id, jobDocVersion) -> {
            CommandManagerJobParameter jobParameter = new CommandManagerJobParameter();
            XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT,
                parser.nextToken(),
                parser
            );

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
                        XContentParserUtils.throwUnknownToken(parser.currentToken(), parser.getTokenLocation());
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
