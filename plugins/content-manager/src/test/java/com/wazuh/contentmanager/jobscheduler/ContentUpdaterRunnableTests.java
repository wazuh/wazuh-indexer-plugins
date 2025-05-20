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
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Path;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.cti.Changes;
import com.wazuh.contentmanager.model.cti.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.updater.ContentUpdater;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.SnapshotManager;

import static org.mockito.Mockito.*;

/** Class for the JobScheduler Content Updater tests. */
public class ContentUpdaterRunnableTests extends OpenSearchTestCase {

    private Environment environment;
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private CTIClient ctiClient;
    private Privileged privileged;
    private CommandManagerClient commandManagerClient;
    private SnapshotManager snapshotManager;
    private ContentUpdater contentUpdater;

    /**
     * Set up the test environment.
     *
     * @throws Exception From OpenSearchTestCase setUp()
     */
    @Before
    public void setup() throws Exception {
        super.setUp();
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
        this.ctiClient = mock(CTIClient.class);
        this.privileged = spy(new Privileged());
        this.commandManagerClient = mock(CommandManagerClient.class);
        this.snapshotManager = mock(SnapshotManager.class);
        this.contentUpdater = mock(ContentUpdater.class);
    }

    /** Reset the singleton instance of ContentUpdaterRunnable for testing purposes. */
    @SuppressForbidden(reason = "unit-test")
    private void resetSingleton() {
        try {
            Field instance = ContentUpdaterRunnable.class.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            instance.set(null, null);
        } catch (Exception e) {
            logger.error("Error resetting singleton: {}", e.getMessage());
            assert (false);
        }
    }

    /**
     * Test a scenario where the run method is called and the offsets are equal.
     *
     * @throws IOException If an error occurs while running the test.
     */
    public void testRun_skipsWhenAlreadyUpToDate() throws IOException {
        resetSingleton();

        ConsumerInfo currentConsumerInfo =
                new ConsumerInfo(
                        PluginSettings.getInstance().getConsumerId(),
                        PluginSettings.getInstance().getContextId(),
                        10L,
                        0L,
                        null);

        ConsumerInfo latestConsumerInfo =
                new ConsumerInfo(
                        PluginSettings.getInstance().getConsumerId(),
                        PluginSettings.getInstance().getContextId(),
                        0L,
                        10L,
                        null);

        doReturn(latestConsumerInfo).when(this.privileged).getConsumerInfo(this.ctiClient);
        doReturn(currentConsumerInfo).when(this.contextIndex).get(anyString(), anyString());

        ContentUpdaterRunnable instance =
                ContentUpdaterRunnable.getInstance(
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.ctiClient,
                        this.privileged,
                        this.commandManagerClient,
                        this.snapshotManager,
                        this.contentUpdater);
        instance.run();

        // Since offsets are equal, no update or snapshot should be triggered.
        verify(this.contentIndex, never()).fromSnapshot(anyString());
        verify(this.contentIndex, never()).patch(any(Changes.class));
    }

    /**
     * Test a scenario where the run method is called and the offsets are different.
     *
     * @throws IOException If an error occurs while running the test.
     */
    public void testRun_triggersSnapshotOnOffsetZero() throws IOException {
        resetSingleton();

        ConsumerInfo currentConsumerInfo =
                new ConsumerInfo(
                        PluginSettings.getInstance().getConsumerId(),
                        PluginSettings.getInstance().getContextId(),
                        0L,
                        0L,
                        null);

        ConsumerInfo latestConsumerInfo =
                new ConsumerInfo(
                        PluginSettings.getInstance().getConsumerId(),
                        PluginSettings.getInstance().getContextId(),
                        0L,
                        20L,
                        null);

        doReturn(latestConsumerInfo).when(this.privileged).getConsumerInfo(this.ctiClient);
        doReturn(currentConsumerInfo).when(this.contextIndex).get(anyString(), anyString());

        doReturn(true).when(this.contextIndex).index(any(ConsumerInfo.class), anyBoolean());

        ContentUpdaterRunnable instance =
                ContentUpdaterRunnable.getInstance(
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.ctiClient,
                        this.privileged,
                        this.commandManagerClient,
                        this.snapshotManager,
                        this.contentUpdater);
        instance.run();

        verify(this.snapshotManager).initialize(latestConsumerInfo);
    }

    /**
     * Test a scenario where the run method is called and the offsets are different.
     *
     * @throws IOException If an error occurs while running the test.
     */
    public void testRun_triggersContentUpdateWhenOffsetsDiffer() throws IOException {
        resetSingleton();
        ConsumerInfo currentConsumerInfo =
                new ConsumerInfo(
                        PluginSettings.getInstance().getConsumerId(),
                        PluginSettings.getInstance().getContextId(),
                        10L,
                        0L,
                        null);

        ConsumerInfo latestConsumerInfo =
                new ConsumerInfo(
                        PluginSettings.getInstance().getConsumerId(),
                        PluginSettings.getInstance().getContextId(),
                        0L,
                        20L,
                        null);

        doReturn(latestConsumerInfo).when(this.privileged).getConsumerInfo(this.ctiClient);
        doReturn(currentConsumerInfo).when(this.contextIndex).get(anyString(), anyString());
        when(this.privileged.getConsumerInfo(this.ctiClient)).thenReturn(latestConsumerInfo);

        when(this.contextIndex.get(anyString(), anyString())).thenReturn(currentConsumerInfo);

        ContentUpdaterRunnable instance =
                ContentUpdaterRunnable.getInstance(
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.ctiClient,
                        this.privileged,
                        this.commandManagerClient,
                        this.snapshotManager,
                        this.contentUpdater);
        instance.run();
        verify(this.contentUpdater).update(currentConsumerInfo, latestConsumerInfo.getLastOffset());
    }

    /**
     * Test a scenario where the run method is called and an IOException occurs.
     *
     * @throws IOException If an error occurs while running the test.
     */
    public void testRun_logsErrorOnIOException() throws IOException {
        resetSingleton();
        ConsumerInfo currentConsumerInfo =
                new ConsumerInfo(
                        PluginSettings.getInstance().getConsumerId(),
                        PluginSettings.getInstance().getContextId(),
                        0L,
                        0L,
                        null);

        ConsumerInfo latestConsumerInfo =
                new ConsumerInfo(
                        PluginSettings.getInstance().getConsumerId(),
                        PluginSettings.getInstance().getContextId(),
                        0L,
                        20L,
                        null);

        doReturn(latestConsumerInfo).when(this.privileged).getConsumerInfo(this.ctiClient);
        doReturn(currentConsumerInfo).when(this.contextIndex).get(anyString(), anyString());
        when(this.privileged.getConsumerInfo(this.ctiClient)).thenReturn(latestConsumerInfo);

        when(this.contextIndex.get(anyString(), anyString()))
                .thenThrow(new IOException("Simulated failure"));

        ContentUpdaterRunnable instance =
                ContentUpdaterRunnable.getInstance(
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.ctiClient,
                        this.privileged,
                        this.commandManagerClient,
                        this.snapshotManager,
                        this.contentUpdater);
        instance.run();

        verify(this.contentUpdater, never())
                .update(currentConsumerInfo, latestConsumerInfo.getLastOffset());
    }

    /** Test a scenario where the run method is called and the job is already running. */
    public void testSingletonEnforcement() {
        resetSingleton();
        ContentUpdaterRunnable instance1 =
                ContentUpdaterRunnable.getInstance(
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.ctiClient,
                        this.privileged,
                        this.commandManagerClient,
                        this.snapshotManager,
                        this.contentUpdater);

        ContentUpdaterRunnable instance2 = ContentUpdaterRunnable.getInstance();

        assert instance1 == instance2;
    }
}
