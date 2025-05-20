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
package com.wazuh.contentmanager.jobscheduler;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.junit.Before;

import java.nio.file.Path;
import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import org.mockito.ArgumentCaptor;

import static org.mockito.Mockito.*;

/** Unit tests for the ContentUpdaterJobRunner class. */
public class ContentUpdaterJobRunnerTests extends OpenSearchTestCase {

    private CTIClient client;
    private ThreadPool threadPool;
    private Environment environment;
    private ContentIndex contentIndex;
    private ContextIndex contextIndex;
    private Privileged privileged;
    private ExecutorService executor;
    private CommandManagerClient commandManagerClient;

    /** Set up the test environment by mocking dependencies. */
    @Before
    public void setup() {
        Path envDir = createTempDir();
        Settings settings =
                Settings.builder()
                        .put("path.home", envDir.toString()) // Required by OpenSearch
                        .putList("path.repo", envDir.toString())
                        .put("content_manager.max_changes", 1000)
                        .put("content_manager.max_concurrent_bulks", 5)
                        .put("content_manager.max_items_per_bulk", 25)
                        .put("content_manager.client.timeout", "10")
                        .put("plugins.security.ssl.http.enabled", false)
                        .put("content_manager.cti.context", "test-context")
                        .put("content_manager.cti.consumer", "test-consumer")
                        .build();
        this.environment = spy(new Environment(settings, envDir));
        when(this.environment.settings()).thenReturn(settings);
        ClusterService clusterService = mock(ClusterService.class);
        PluginSettings pluginSettings =
                PluginSettings.getInstance(this.environment.settings(), clusterService);
        Client client = mock(Client.class);
        this.contextIndex = spy(new ContextIndex(client, pluginSettings));
        this.contentIndex = spy(new ContentIndex(client, pluginSettings));
        this.threadPool = mock(ThreadPool.class);
        this.privileged = spy(new Privileged());
        this.executor = mock(ExecutorService.class);
        this.commandManagerClient = mock(CommandManagerClient.class);

        when(threadPool.generic()).thenReturn(executor);
    }

    /** Test the singleton instance of ContentUpdaterJobRunner. */
    public void testSingletonInstance() {
        ContentUpdaterJobRunner instance1 =
                ContentUpdaterJobRunner.getInstance(
                        this.client,
                        this.threadPool,
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.privileged,
                        this.commandManagerClient);
        ContentUpdaterJobRunner instance2 = ContentUpdaterJobRunner.getInstance();
        assertSame(instance1, instance2);
    }

    /** Test the constructor of ContentUpdaterJobRunner. */
    public void testSetters() {
        ContentUpdaterJobRunner runner = ContentUpdaterJobRunner.getInstance();
        runner.setClient(this.client);
        runner.setThreadPool(this.threadPool);
        runner.setEnvironment(this.environment);
        runner.setContentIndex(this.contentIndex);
        runner.setContextIndex(this.contextIndex);
        runner.setPrivileged(this.privileged);
    }

    /** Test the runJob method of ContentUpdaterJobRunner. */
    public void testRunJobSubmitsRunnable() {
        ContentUpdaterJobRunner runner =
                ContentUpdaterJobRunner.getInstance(
                        this.client,
                        this.threadPool,
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.privileged,
                        this.commandManagerClient);

        ScheduledJobParameter jobParam = mock(ScheduledJobParameter.class);
        JobExecutionContext jobContext = mock(JobExecutionContext.class);

        runner.runJob(jobParam, jobContext);

        ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
        verify(this.executor, times(1)).submit(captor.capture());
        assertTrue(captor.getValue() instanceof ContentUpdaterRunnable);
    }
}
