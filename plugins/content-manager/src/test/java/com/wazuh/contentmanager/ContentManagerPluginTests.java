/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.jobscheduler.jobs.TelemetryPingJob;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for the {@link ContentManagerPlugin} class. */
public class ContentManagerPluginTests extends OpenSearchTestCase {

    private ContentManagerPlugin plugin;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ThreadPool threadPool;
    @Mock private DiscoveryNode discoveryNode;
    @Mock private CatalogSyncJob catalogSyncJob;
    @Mock private TelemetryPingJob telemetryPingJob;
    @Mock private ConsumersIndex consumersIndex;

    /** Sets up the test environment before each test method. */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.plugin = new ContentManagerPlugin();

        ExecutorService mockExecutor = mock(ExecutorService.class);
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(mockExecutor)
                .execute(any(Runnable.class));
        when(this.threadPool.generic()).thenReturn(mockExecutor);

        this.injectField(this.plugin, "client", this.client);
        this.injectField(this.plugin, "threadPool", this.threadPool);
        this.injectField(this.plugin, "catalogSyncJob", this.catalogSyncJob);
        this.injectField(this.plugin, "telemetryPingJob", this.telemetryPingJob);
        this.injectField(this.plugin, "consumersIndex", this.consumersIndex);

        ContentManagerPluginTests.clearInstance();
    }

    /** Cleans up the test environment after each test method. */
    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        ContentManagerPluginTests.clearInstance();
        super.tearDown();
    }

    /** Tests that catalogSyncJob.trigger() is called when update_on_start is true (default). */
    public void testOnNodeStartedTriggerEnabled() {
        // Initialize settings with update_on_start = true
        Settings settings =
                Settings.builder().put("plugins.content_manager.catalog.update_on_start", true).build();
        PluginSettings.getInstance(settings);

        when(this.discoveryNode.isClusterManagerNode()).thenReturn(true);

        // Act
        this.plugin.onNodeStarted(this.discoveryNode);

        // Assert
        verify(this.catalogSyncJob).trigger();
    }

    /** Tests that catalogSyncJob.trigger() is NOT called when update_on_start is false. */
    public void testOnNodeStartedTriggerDisabled() {
        // Initialize settings with update_on_start = false
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.catalog.update_on_start", false)
                        .put("plugins.content_manager.telemetry.enabled", false)
                        .build();
        PluginSettings.getInstance(settings);

        when(this.discoveryNode.isClusterManagerNode()).thenReturn(true);

        // Act
        this.plugin.onNodeStarted(this.discoveryNode);

        // Assert
        verify(this.catalogSyncJob, never()).trigger();
    }

    /**
     * Tests that {@code telemetryPingJob.trigger()} is NOT invoked when telemetry is disabled —
     * registration is skipped and the immediate ping must not run.
     */
    public void testOnNodeStartedTelemetryDisabledDoesNotTriggerPing() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.catalog.update_on_start", false)
                        .put("plugins.content_manager.telemetry.enabled", false)
                        .build();
        PluginSettings.getInstance(settings);

        when(this.discoveryNode.isClusterManagerNode()).thenReturn(true);

        this.plugin.onNodeStarted(this.discoveryNode);

        verify(this.telemetryPingJob, never()).trigger();
    }

    /**
     * Tests that {@code telemetryPingJob.trigger()} is NOT invoked when registration fails. The
     * client chain is left unmocked so the scheduler path throws inside its try/catch — proving the
     * immediate ping only runs after a successful registration.
     */
    public void testOnNodeStartedTelemetryTriggerGatedByRegistration() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.catalog.update_on_start", false)
                        .put("plugins.content_manager.telemetry.enabled", true)
                        .build();
        PluginSettings.getInstance(settings);

        when(this.discoveryNode.isClusterManagerNode()).thenReturn(true);

        this.plugin.onNodeStarted(this.discoveryNode);

        verify(this.telemetryPingJob, never()).trigger();
    }

    /**
     * Tests that a failed telemetry-scheduling attempt schedules exactly one retry with the expected
     * backoff delay on the generic pool. The client chain is left unmocked so {@code
     * ensureJobsIndexExists} throws inside the try/catch.
     */
    public void testTelemetryRetryScheduledOnFirstFailure() throws Exception {
        Settings settings =
                Settings.builder().put("plugins.content_manager.telemetry.enabled", true).build();
        PluginSettings.getInstance(settings);

        Method method =
                ContentManagerPlugin.class.getDeclaredMethod("scheduleTelemetryPingJob", int.class);
        method.setAccessible(true);
        method.invoke(this.plugin, 0);

        long expectedDelay = (long) Constants.JOB_SCHEDULE_RETRY_BACKOFF_SECONDS;
        verify(this.threadPool)
                .schedule(
                        any(Runnable.class),
                        eq(TimeValue.timeValueSeconds(expectedDelay)),
                        eq(ThreadPool.Names.GENERIC));
    }

    /**
     * Tests that once the retry budget is exhausted, no further retry is scheduled. The private
     * method is invoked with {@code attempt == MAX_JOB_SCHEDULE_RETRIES} so the catch branch lands on
     * the "give up" path.
     */
    public void testTelemetryGiveUpAfterMaxRetries() throws Exception {
        Settings settings =
                Settings.builder().put("plugins.content_manager.telemetry.enabled", true).build();
        PluginSettings.getInstance(settings);

        Method method =
                ContentManagerPlugin.class.getDeclaredMethod("scheduleTelemetryPingJob", int.class);
        method.setAccessible(true);
        method.invoke(this.plugin, Constants.MAX_JOB_SCHEDULE_RETRIES);

        verify(this.threadPool, never())
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
    }

    /**
     * Tests that a failed catalog-sync-scheduling attempt schedules exactly one retry with the
     * expected backoff delay.
     */
    public void testCatalogSyncRetryScheduledOnFirstFailure() throws Exception {
        PluginSettings.getInstance(Settings.EMPTY);

        Method method =
                ContentManagerPlugin.class.getDeclaredMethod("scheduleCatalogSyncJob", int.class);
        method.setAccessible(true);
        method.invoke(this.plugin, 0);

        long expectedDelay = (long) Constants.JOB_SCHEDULE_RETRY_BACKOFF_SECONDS;
        verify(this.threadPool)
                .schedule(
                        any(Runnable.class),
                        eq(TimeValue.timeValueSeconds(expectedDelay)),
                        eq(ThreadPool.Names.GENERIC));
    }

    /** Tests that catalogSyncJob.trigger() is NOT called on a non-cluster-manager node. */
    public void testOnNodeStartedNonClusterManager() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.catalog.update_on_start", true).build();
        PluginSettings.getInstance(settings);

        when(this.discoveryNode.isClusterManagerNode()).thenReturn(false);

        // Act
        this.plugin.onNodeStarted(this.discoveryNode);

        // Assert
        verify(this.catalogSyncJob, never()).trigger();
    }

    /** Helper to inject private fields via reflection. */
    @SuppressForbidden(reason = "Unit test injection")
    private void injectField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    /**
     * Helper to reset PluginSettings singleton.
     *
     * @throws Exception In case of reflection errors
     */
    @SuppressForbidden(reason = "Unit test reset")
    public static void clearInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }
}
