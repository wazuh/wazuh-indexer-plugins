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

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
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
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.jobscheduler.ContentUpdaterJobParameter;
import com.wazuh.contentmanager.jobscheduler.ContentUpdaterJobRunner;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.SnapshotHelper;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin
        implements ClusterPlugin, ActionPlugin, JobSchedulerExtension {
    /** Scheduled jobs index name. */
    public static final String JOB_INDEX = ".content_updater_jobs";

    /** Scheduled job ID. */
    public static final String JOB_ID = "content_updater_job";

    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private Environment environment;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private Client client;

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
        this.contentIndex = new ContentIndex(client);
        this.environment = environment;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.client = client;
        ContentUpdaterJobRunner.getInstance(client, threadPool);

        return Collections.emptyList();
    }

    /**
     * Call the CTI API on startup and get the latest consumer information into an index
     *
     * @param localNode local Node info
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        SnapshotHelper snapshotHelper =
                new SnapshotHelper(this.threadPool, this.environment, this.contextIndex, this.contentIndex);
        this.clusterService.addListener(snapshotHelper);

        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
        ContentUpdaterJobParameter jobParameter =
                new ContentUpdaterJobParameter("update_content", schedule);
        IndexRequest indexRequest = null;
        try {
            indexRequest =
                    new IndexRequest()
                            .index(JOB_INDEX)
                            .id(JOB_ID)
                            .source(jobParameter.toXContent(JsonXContent.contentBuilder(), null))
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        this.client.index(indexRequest).actionGet(5, TimeUnit.SECONDS);
    }

    /**
     * Returns the settings for the plugin.
     *
     * @return the settings for the plugin
     */
    @Override
    public List<Setting<?>> getSettings() {
        return Collections.singletonList(PluginSettings.CTI_API_URL);
    }

    @Override
    public String getJobType() {
        return "content_updater";
    }

    @Override
    public String getJobIndex() {
        return ".content_updater_jobs";
    }

    @Override
    public ScheduledJobRunner getJobRunner() {
        return ContentUpdaterJobRunner.getInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
        return (parser, id, jobDocVersion) -> {
            ContentUpdaterJobParameter jobParameter = new ContentUpdaterJobParameter();
            XContentParserUtils.ensureExpectedToken(
                    XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

            while (!parser.nextToken().equals(XContentParser.Token.END_OBJECT)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case ContentUpdaterJobParameter.NAME_FIELD:
                        jobParameter.setJobName(parser.text());
                        break;
                    case ContentUpdaterJobParameter.ENABLED_FIELD:
                        jobParameter.setEnabled(parser.booleanValue());
                        break;
                    case ContentUpdaterJobParameter.ENABLED_TIME_FIELD:
                        jobParameter.setEnabledTime(parseInstantValue(parser));
                        break;
                    case ContentUpdaterJobParameter.LAST_UPDATE_TIME_FIELD:
                        jobParameter.setLastUpdateTime(parseInstantValue(parser));
                        break;
                    case ContentUpdaterJobParameter.SCHEDULE_FIELD:
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
}
