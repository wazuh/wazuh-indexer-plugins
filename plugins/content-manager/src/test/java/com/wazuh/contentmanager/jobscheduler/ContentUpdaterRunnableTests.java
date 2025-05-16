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
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.nio.file.Path;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;

import static org.mockito.Mockito.*;

/** Class for the JobScheduler Content Updater tests. */
public class ContentUpdaterRunnableTests extends OpenSearchTestCase {

    private Environment environment;
    private Client client;
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private CTIClient ctiClient;
    private Privileged privileged;
    private ContentUpdaterRunnable runnable;
    private PluginSettings pluginSettings;
    private ClusterService clusterService;
    private CommandManagerClient commandManagerClient;

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
                        .build();
        this.environment = spy(new Environment(settings, envDir));
        when(this.environment.settings()).thenReturn(settings);
        this.clusterService = mock(ClusterService.class);
        this.pluginSettings =
                PluginSettings.getInstance(this.environment.settings(), this.clusterService);
        this.client = mock(Client.class);
        this.contextIndex = spy(new ContextIndex(this.client, this.pluginSettings));
        this.contentIndex = spy(new ContentIndex(this.client, this.pluginSettings));
        this.ctiClient = mock(CTIClient.class);
        this.privileged = spy(new Privileged());
        this.commandManagerClient = mock(CommandManagerClient.class);

        this.runnable =
                ContentUpdaterRunnable.getInstance(
                        this.environment,
                        this.contextIndex,
                        this.contentIndex,
                        this.ctiClient,
                        this.privileged,
                        this.commandManagerClient);
    }

    /** Test the getInstance method. */
    public void testGetInstance() {
        assert (this.runnable.equals(ContentUpdaterRunnable.getInstance()));
    }

    public void testIsRunningTrue() {

    }
}
