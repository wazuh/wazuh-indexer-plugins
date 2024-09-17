/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
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
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Supplier;

/**
 * The Command Manager plugin is a JobScheduler extension plugin.
 * <p>
 * It uses ".commands" index to manage its scheduled jobs, and exposes a REST API
 * endpoint using {\@link SampleExtensionRestHandler}.
 */
public class CommandManagerPlugin extends Plugin implements JobSchedulerExtension {
    static final String JOB_INDEX_NAME = ".commands";
    private static final Logger log = LogManager.getLogger(CommandManagerPlugin.class);

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
        CommandManagerJobRunner jobRunner = CommandManagerJobRunner.getJobRunnerInstance();
        jobRunner.setClusterService(clusterService);
        jobRunner.setThreadPool(threadPool);
        jobRunner.setClient(client);

        return Collections.emptyList();
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
        return CommandManagerJobRunner.getJobRunnerInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
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
                    case CommandManagerJobParameter.ENABLED_FILED:
                        jobParameter.setEnabled(parser.booleanValue());
                        break;
                    case CommandManagerJobParameter.ENABLED_TIME_FILED:
                        jobParameter.setEnabledTime(parseInstantValue(parser));
                        break;
                    case CommandManagerJobParameter.LAST_UPDATE_TIME_FIELD:
                        jobParameter.setLastUpdateTime(parseInstantValue(parser));
                        break;
                    case CommandManagerJobParameter.SCHEDULE_FIELD:
                        jobParameter.setSchedule(ScheduleParser.parse(parser));
                        break;
                    case CommandManagerJobParameter.INDEX_NAME_FIELD:
                        jobParameter.setIndexToWatch(parser.text());
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
}
