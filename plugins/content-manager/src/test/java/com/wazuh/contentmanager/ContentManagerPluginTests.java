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

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.LocalNodeClusterManagerListener;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Before;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.jobscheduler.jobs.TelemetryPingJob;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for the {@link ContentManagerPlugin} class. */
public class ContentManagerPluginTests extends OpenSearchTestCase {

    private ContentManagerPlugin plugin;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ClusterService clusterService;
    @Mock private ThreadPool threadPool;
    @Mock private DiscoveryNode discoveryNode;
    @Mock private CatalogSyncJob catalogSyncJob;
    @Mock private TelemetryPingJob telemetryPingJob;
    @Mock private EngineContentLoader engineContentLoader;
    @Mock private SpaceService spaceService;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private ClusterState clusterState;
    @Mock private DiscoveryNodes discoveryNodes;
    @Mock private Metadata metadata;

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

        when(this.clusterService.state()).thenReturn(this.clusterState);
        when(this.clusterState.nodes()).thenReturn(this.discoveryNodes);
        when(this.clusterState.metadata()).thenReturn(this.metadata);
        when(this.metadata.clusterUUID()).thenReturn("test-cluster-uuid");
        when(this.discoveryNodes.isLocalNodeElectedClusterManager()).thenReturn(false);

        this.injectField(this.plugin, "client", this.client);
        this.injectField(this.plugin, "clusterService", this.clusterService);
        this.injectField(this.plugin, "threadPool", this.threadPool);
        this.injectField(this.plugin, "catalogSyncJob", this.catalogSyncJob);
        this.injectField(this.plugin, "telemetryPingJob", this.telemetryPingJob);
        this.injectField(this.plugin, "engineContentLoader", this.engineContentLoader);
        this.injectField(this.plugin, "spaceService", this.spaceService);
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
        Settings settings =
                Settings.builder().put("plugins.content_manager.catalog.update_on_start", true).build();
        PluginSettings.getInstance(settings);

        this.plugin.onNodeStarted(this.discoveryNode);
        this.simulateClusterManagerElection();

        verify(this.catalogSyncJob).trigger();
    }

    /** Tests that catalogSyncJob.trigger() is NOT called when update_on_start is false. */
    public void testOnNodeStartedTriggerDisabled() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.catalog.update_on_start", false)
                        .put("plugins.content_manager.telemetry.enabled", false)
                        .build();
        PluginSettings.getInstance(settings);

        this.plugin.onNodeStarted(this.discoveryNode);
        this.simulateClusterManagerElection();

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

        this.plugin.onNodeStarted(this.discoveryNode);
        this.simulateClusterManagerElection();

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

        this.plugin.onNodeStarted(this.discoveryNode);
        this.simulateClusterManagerElection();

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

        this.invokePrivateIntMethod("scheduleTelemetryPingJob", 0);

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

        this.invokePrivateIntMethod("scheduleTelemetryPingJob", Constants.MAX_JOB_SCHEDULE_RETRIES);

        verify(this.threadPool, never())
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
    }

    /**
     * Tests that a failed catalog-sync-scheduling attempt schedules exactly one retry with the
     * expected backoff delay.
     */
    public void testCatalogSyncRetryScheduledOnFirstFailure() throws Exception {
        PluginSettings.getInstance(Settings.EMPTY);

        this.invokePrivateIntMethod("scheduleCatalogSyncJob", 0);

        long expectedDelay = (long) Constants.JOB_SCHEDULE_RETRY_BACKOFF_SECONDS;
        verify(this.threadPool)
                .schedule(
                        any(Runnable.class),
                        eq(TimeValue.timeValueSeconds(expectedDelay)),
                        eq(ThreadPool.Names.GENERIC));
    }

    /**
     * Tests that a transient standard-space-hash read failure registers a cluster-state listener to
     * retry, instead of scheduling a bounded backoff. The spaceService mock calls {@code onFailure}
     * to simulate the "all shards failed" startup condition.
     */
    public void testStandardSpaceHashRegistersListenerOnTransientFailure() throws Exception {
        PluginSettings.getInstance(Settings.EMPTY);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<?>>getArgument(1)
                                    .onFailure(new RuntimeException("all shards failed"));
                            return null;
                        })
                .when(this.spaceService)
                .recalculateSpaceHashIfMissing(anyString(), any());

        this.invokePrivateMethod("ensureStandardSpaceHash");

        // A cluster-state listener is registered so the read is retried on the next state update;
        // no bounded backoff is scheduled on the thread pool.
        verify(this.clusterService).addListener(any(ClusterStateListener.class));
        verify(this.threadPool, never())
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
    }

    /**
     * Tests that a successful standard-space-hash read does not register any retry listener: there is
     * nothing to retry.
     */
    public void testStandardSpaceHashDoesNotRegisterListenerOnSuccess() throws Exception {
        PluginSettings.getInstance(Settings.EMPTY);
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Set<String>>>getArgument(1).onResponse(new HashSet<>());
                            return null;
                        })
                .when(this.spaceService)
                .recalculateSpaceHashIfMissing(anyString(), any());

        this.invokePrivateMethod("ensureStandardSpaceHash");

        verify(this.clusterService, never()).addListener(any(ClusterStateListener.class));
    }

    /**
     * Tests that the retry listener keeps reattempting on cluster-state updates and, once the read
     * finally succeeds, deregisters itself so the policy read does not run on every future update.
     */
    public void testStandardSpaceHashListenerRetriesUntilSuccessAndDeregisters() throws Exception {
        PluginSettings.getInstance(Settings.EMPTY);
        // Fail the first attempt (registers the listener), succeed on the second (fired by the
        // listener), returning an empty changed-set so no Engine reload is broadcast.
        final int[] calls = {0};
        doAnswer(
                        invocation -> {
                            ActionListener<Set<String>> listener = invocation.getArgument(1);
                            if (calls[0]++ == 0) {
                                listener.onFailure(new RuntimeException("all shards failed"));
                            } else {
                                listener.onResponse(new HashSet<>());
                            }
                            return null;
                        })
                .when(this.spaceService)
                .recalculateSpaceHashIfMissing(anyString(), any());

        this.invokePrivateMethod("ensureStandardSpaceHash");

        ArgumentCaptor<ClusterStateListener> captor =
                ArgumentCaptor.forClass(ClusterStateListener.class);
        verify(this.clusterService).addListener(captor.capture());

        // Simulate the next cluster-state update: the retry succeeds and the listener is removed.
        captor.getValue().clusterChanged(null);

        verify(this.clusterService).removeListener(captor.getValue());
    }

    /** Tests that catalogSyncJob.trigger() is NOT called when the node is not elected leader. */
    public void testOnNodeStartedNonClusterManager() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.catalog.update_on_start", true).build();
        PluginSettings.getInstance(settings);

        this.plugin.onNodeStarted(this.discoveryNode);

        verify(this.catalogSyncJob, never()).trigger();
    }

    /**
     * Regression test for issue #1362: {@code ensureResourceIndicesExist} must scan every space-aware
     * ruleset resource index, so they are bootstrapped at startup even when catalog synchronization
     * is disabled. Here every index reports as already existing, so the method should only probe for
     * existence (one async {@code exists} per index) and create nothing.
     */
    public void testEnsureResourceIndicesChecksAllResourceIndices() throws Exception {
        PluginSettings.getInstance(Settings.EMPTY);

        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        IndicesExistsResponse existsResponse = mock(IndicesExistsResponse.class);
        when(existsResponse.isExists()).thenReturn(true);

        when(this.client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        doAnswer(
                        invocation -> {
                            ActionListener<IndicesExistsResponse> l = invocation.getArgument(1);
                            l.onResponse(existsResponse);
                            return null;
                        })
                .when(indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any(ActionListener.class));

        this.invokePrivateMethod("ensureResourceIndicesExist");

        // Every resource index is probed exactly once via the async exists() API; nothing is created
        // because all of them report as already existing.
        ArgumentCaptor<IndicesExistsRequest> requestCaptor =
                ArgumentCaptor.forClass(IndicesExistsRequest.class);
        verify(indicesAdminClient, times(Constants.RESOURCE_INDEX_MAPPINGS.size()))
                .exists(requestCaptor.capture(), any(ActionListener.class));

        Set<String> probedIndices = new HashSet<>();
        for (IndicesExistsRequest request : requestCaptor.getAllValues()) {
            probedIndices.addAll(Arrays.asList(request.indices()));
        }
        assertEquals(Constants.RESOURCE_INDEX_MAPPINGS.keySet(), probedIndices);
        verify(indicesAdminClient, never()).create(any());
    }

    /**
     * Guards against a broken {@link Constants#RESOURCE_INDEX_MAPPINGS} entry: every mapped index
     * must point at a mapping file that actually exists on the classpath, otherwise startup creation
     * would silently fail with "no mappings".
     */
    public void testResourceIndexMappingsResolveToClasspathResources() throws Exception {
        assertFalse(Constants.RESOURCE_INDEX_MAPPINGS.isEmpty());
        for (String mappingPath : Constants.RESOURCE_INDEX_MAPPINGS.values()) {
            try (InputStream is = ContentManagerPlugin.class.getResourceAsStream(mappingPath)) {
                assertNotNull("Missing mapping resource on classpath: " + mappingPath, is);
            }
        }
    }

    /** Captures the registered {@link LocalNodeClusterManagerListener} and fires onClusterManager. */
    private void simulateClusterManagerElection() {
        ArgumentCaptor<LocalNodeClusterManagerListener> captor =
                ArgumentCaptor.forClass(LocalNodeClusterManagerListener.class);
        verify(this.clusterService).addLocalNodeClusterManagerListener(captor.capture());
        captor.getValue().onClusterManager();
    }

    /** Helper to inject private fields via reflection. */
    @SuppressForbidden(reason = "Unit test injection")
    private void injectField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    /** Helper to invoke a private no-arg {@code void method()} on the plugin via reflection. */
    @SuppressForbidden(reason = "Unit test reflection")
    private void invokePrivateMethod(String methodName) throws Exception {
        Method method = ContentManagerPlugin.class.getDeclaredMethod(methodName);
        method.setAccessible(true);
        method.invoke(this.plugin);
    }

    /** Helper to invoke a private {@code void method(int)} on the plugin via reflection. */
    @SuppressForbidden(reason = "Unit test reflection")
    private void invokePrivateIntMethod(String methodName, int value) throws Exception {
        Method method = ContentManagerPlugin.class.getDeclaredMethod(methodName, int.class);
        method.setAccessible(true);
        method.invoke(this.plugin, value);
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
