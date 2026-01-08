package com.wazuh.contentmanager;

import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.junit.After;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.lang.reflect.Field;
import java.util.concurrent.ExecutorService;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link ContentManagerPlugin} class.
 */
public class ContentManagerPluginTests extends OpenSearchTestCase {

    private ContentManagerPlugin plugin;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ThreadPool threadPool;
    @Mock private DiscoveryNode discoveryNode;
    @Mock private CatalogSyncJob catalogSyncJob;

    /**
     * Sets up the test environment before each test method.
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.plugin = new ContentManagerPlugin();

        when(this.threadPool.generic()).thenReturn(mock(ExecutorService.class));

        this.injectField(this.plugin, "client", this.client);
        this.injectField(this.plugin, "threadPool", this.threadPool);
        this.injectField(this.plugin, "catalogSyncJob", this.catalogSyncJob);

        clearInstance();
    }

    /**
     * Cleans up the test environment after each test method.
     */
    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        clearInstance();
        super.tearDown();
    }

    /**
     * Tests that catalogSyncJob.trigger() is called when update_on_start is true (default).
     */
    public void testOnNodeStartedTriggerEnabled() {
        // Initialize settings with update_on_start = true
        Settings settings = Settings.builder()
            .put("plugins.content_manager.catalog.update_on_start", true)
            .build();
        PluginSettings.getInstance(settings);

        // Act
        this.plugin.onNodeStarted(this.discoveryNode);

        // Assert
        verify(this.catalogSyncJob).trigger();
    }

    /**
     * Tests that catalogSyncJob.trigger() is NOT called when update_on_start is false.
     */
    public void testOnNodeStartedTriggerDisabled() {
        // Initialize settings with update_on_start = false
        Settings settings = Settings.builder()
            .put("plugins.content_manager.catalog.update_on_start", false)
            .build();
        PluginSettings.getInstance(settings);

        // Act
        this.plugin.onNodeStarted(this.discoveryNode);

        // Assert
        verify(this.catalogSyncJob, never()).trigger();
    }

    /**
     * Helper to inject private fields via reflection.
     */
    @SuppressForbidden(reason = "Unit test injection")
    private void injectField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    /**
     * Helper to reset PluginSettings singleton.
     */
    @SuppressForbidden(reason = "Unit test reset")
    public static void clearInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }
}
