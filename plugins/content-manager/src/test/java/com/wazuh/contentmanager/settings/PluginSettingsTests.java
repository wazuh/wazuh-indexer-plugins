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
package com.wazuh.contentmanager.settings;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;

import com.wazuh.contentmanager.utils.Constants;

public class PluginSettingsTests extends OpenSearchTestCase {

    /**
     * Set up the tests. Resets the singleton instance before each test to ensure isolation.
     *
     * @throws Exception rethrown from parent method or reflection operations
     */
    @Before
    public void setUp() throws Exception {
        super.setUp();
        PluginSettingsTests.clearInstance();
    }

    /**
     * Tear down the tests. Resets the singleton instance after each test to ensure isolation.
     *
     * @throws Exception rethrown from parent method or reflection operations
     */
    @After
    public void tearDown() throws Exception {
        PluginSettingsTests.clearInstance();
        super.tearDown();
    }

    /**
     * Helper method to reset the Singleton instance of PluginSettings via reflection.
     *
     * @throws Exception if reflection fails
     */
    @SuppressForbidden(reason = "Unit test reset")
    public static void clearInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    /**
     * Test the default values of the settings. Verifies that update_on_start and update_on_schedule
     * are true by default.
     */
    public void testDefaultSettings() {
        // Initialize with empty settings
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);

        // Verify default values
        Assert.assertTrue(pluginSettings.isUpdateOnStart());
        Assert.assertTrue(pluginSettings.isUpdateOnSchedule());
        Assert.assertEquals("", pluginSettings.getCatalogRuleset());
        Assert.assertEquals("", pluginSettings.getCatalogIocs());
        Assert.assertEquals("", pluginSettings.getCatalogVulnerabilities());
    }

    /**
     * Test custom values for the settings. Verifies that the settings correctly reflect the provided
     * configuration.
     */
    public void testCustomSettings() {
        // Initialize with custom settings
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.catalog.update_on_start", false)
                        .put("plugins.content_manager.catalog.update_on_schedule", false)
                        .put(
                                "plugins.content_manager.catalog.ruleset",
                                "https://cti.example/api/v1/catalog/contexts/c1/consumers/rules")
                        .put(
                                "plugins.content_manager.catalog.iocs",
                                "https://cti.example/api/v1/catalog/contexts/c2/consumers/iocs")
                        .put(
                                "plugins.content_manager.catalog.vulnerabilities",
                                "https://cti.example/api/v1/catalog/contexts/c3/consumers/vulns")
                        .build();

        PluginSettings pluginSettings = PluginSettings.getInstance(settings);

        // Verify custom values
        Assert.assertFalse(pluginSettings.isUpdateOnStart());
        Assert.assertFalse(pluginSettings.isUpdateOnSchedule());
        Assert.assertEquals(
                "https://cti.example/api/v1/catalog/contexts/c1/consumers/rules",
                pluginSettings.getCatalogRuleset());
        Assert.assertEquals(
                "https://cti.example/api/v1/catalog/contexts/c2/consumers/iocs",
                pluginSettings.getCatalogIocs());
        Assert.assertEquals(
                "https://cti.example/api/v1/catalog/contexts/c3/consumers/vulns",
                pluginSettings.getCatalogVulnerabilities());
    }

    /** Tests that max_bulk_bytes defaults to 5 MB when not configured. */
    public void testMaxBulkBytesDefault() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        Assert.assertEquals(5L * 1024 * 1024, pluginSettings.getMaxBulkBytes());
    }

    /** Tests that a custom max_bulk_bytes value within bounds is honored. */
    public void testMaxBulkBytesCustom() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.max_bulk_bytes", 8L * 1024 * 1024).build();
        PluginSettings pluginSettings = PluginSettings.getInstance(settings);
        Assert.assertEquals(8L * 1024 * 1024, pluginSettings.getMaxBulkBytes());
    }

    /** Tests that a max_bulk_bytes below the 1 MB floor is rejected. */
    public void testMaxBulkBytesBelowMinThrows() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.max_bulk_bytes", 1024L).build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /** Tests that a max_bulk_bytes above the 100 MB ceiling is rejected. */
    public void testMaxBulkBytesAboveMaxThrows() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.max_bulk_bytes", 200L * 1024 * 1024)
                        .build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /** Tests that the Setup-wait backoff settings fall back to their documented defaults. */
    public void testSetupWaitBackoffDefaults() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        Assert.assertEquals(4, pluginSettings.getSetupWaitMaxRetries());
        Assert.assertEquals(20, pluginSettings.getSetupWaitBackoffBaseSeconds());
    }

    /** Tests that custom Setup-wait backoff values within bounds are honored. */
    public void testSetupWaitBackoffCustom() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.setup_wait.max_retries", 6)
                        .put("plugins.content_manager.setup_wait.backoff_base_seconds", 45)
                        .build();
        PluginSettings pluginSettings = PluginSettings.getInstance(settings);
        Assert.assertEquals(6, pluginSettings.getSetupWaitMaxRetries());
        Assert.assertEquals(45, pluginSettings.getSetupWaitBackoffBaseSeconds());
    }

    /** Tests that a negative setup_wait.max_retries is rejected. */
    public void testSetupWaitMaxRetriesBelowMinThrows() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.setup_wait.max_retries", -1).build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /** Tests that a setup_wait.max_retries above the documented ceiling is rejected. */
    public void testSetupWaitMaxRetriesAboveMaxThrows() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.setup_wait.max_retries", 11).build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /** Tests that a setup_wait.backoff_base_seconds below the 1s floor is rejected. */
    public void testSetupWaitBackoffBaseSecondsBelowMinThrows() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.setup_wait.backoff_base_seconds", 0)
                        .build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /** Tests that a setup_wait.backoff_base_seconds above the documented ceiling is rejected. */
    public void testSetupWaitBackoffBaseSecondsAboveMaxThrows() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.setup_wait.backoff_base_seconds", 121)
                        .build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /** Tests that the resource limit settings fall back to their documented defaults. */
    public void testResourceLimitDefaults() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);

        Assert.assertEquals(100, pluginSettings.getMaxIntegrations());
        Assert.assertEquals(200, pluginSettings.getMaxDecoders());
        Assert.assertEquals(200, pluginSettings.getMaxRules());
        Assert.assertEquals(100, pluginSettings.getMaxKvdbs());
        Assert.assertEquals(100, pluginSettings.getMaxFilters());
    }

    /** Tests that the resource limit settings have no upper bound. */
    public void testResourceLimitsHaveNoUpperBound() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.max_integrations", 100_000)
                        .put("plugins.content_manager.max_decoders", 100_000)
                        .put("plugins.content_manager.max_rules", 100_000)
                        .put("plugins.content_manager.max_kvdbs", 100_000)
                        .put("plugins.content_manager.max_filters", 100_000)
                        .build();

        PluginSettings pluginSettings = PluginSettings.getInstance(settings);

        Assert.assertEquals(100_000, pluginSettings.getMaxIntegrations());
        Assert.assertEquals(100_000, pluginSettings.getMaxDecoders());
        Assert.assertEquals(100_000, pluginSettings.getMaxRules());
        Assert.assertEquals(100_000, pluginSettings.getMaxKvdbs());
        Assert.assertEquals(100_000, pluginSettings.getMaxFilters());
    }

    /** Tests that the resource limit settings accept Integer.MAX_VALUE. */
    public void testResourceLimitsAcceptIntegerMaxValue() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.max_integrations", Integer.MAX_VALUE)
                        .put("plugins.content_manager.max_decoders", Integer.MAX_VALUE)
                        .put("plugins.content_manager.max_rules", Integer.MAX_VALUE)
                        .put("plugins.content_manager.max_kvdbs", Integer.MAX_VALUE)
                        .put("plugins.content_manager.max_filters", Integer.MAX_VALUE)
                        .build();

        PluginSettings pluginSettings = PluginSettings.getInstance(settings);

        Assert.assertEquals(Integer.MAX_VALUE, pluginSettings.getMaxIntegrations());
        Assert.assertEquals(Integer.MAX_VALUE, pluginSettings.getMaxDecoders());
        Assert.assertEquals(Integer.MAX_VALUE, pluginSettings.getMaxRules());
        Assert.assertEquals(Integer.MAX_VALUE, pluginSettings.getMaxKvdbs());
        Assert.assertEquals(Integer.MAX_VALUE, pluginSettings.getMaxFilters());
    }

    /** Tests that the resource limit settings keep their zero floor. */
    public void testResourceLimitsRejectNegativeValues() {
        Assert.assertThrows(
                IllegalArgumentException.class,
                () ->
                        PluginSettings.MAX_DECODERS.get(
                                Settings.builder().put("plugins.content_manager.max_decoders", -1).build()));
        Assert.assertThrows(
                IllegalArgumentException.class,
                () ->
                        PluginSettings.MAX_FILTERS.get(
                                Settings.builder().put("plugins.content_manager.max_filters", -1).build()));
    }

    /** Tests that zero is still a valid resource limit, blocking creation of that resource. */
    public void testResourceLimitsAcceptZero() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.max_integrations", 0)
                        .put("plugins.content_manager.max_decoders", 0)
                        .put("plugins.content_manager.max_rules", 0)
                        .put("plugins.content_manager.max_kvdbs", 0)
                        .put("plugins.content_manager.max_filters", 0)
                        .build();

        PluginSettings pluginSettings = PluginSettings.getInstance(settings);

        Assert.assertEquals(0, pluginSettings.getMaxIntegrations());
        Assert.assertEquals(0, pluginSettings.getMaxDecoders());
        Assert.assertEquals(0, pluginSettings.getMaxRules());
        Assert.assertEquals(0, pluginSettings.getMaxKvdbs());
        Assert.assertEquals(0, pluginSettings.getMaxFilters());
    }

    /** Tests that getUserAgent returns the fallback value when no version has been set. */
    public void testGetUserAgentDefaultsToUnknown() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);

        Assert.assertNull(pluginSettings.getVersion());
        Assert.assertEquals(Constants.USER_AGENT_PREFIX + "unknown", pluginSettings.getUserAgent());
    }

    /** Tests that getUserAgent returns the correct value after setWazuhVersion is called. */
    public void testGetUserAgentWithVersion() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setVersion("5.0.0");

        Assert.assertEquals("5.0.0", pluginSettings.getVersion());
        Assert.assertEquals(Constants.USER_AGENT_PREFIX + "5.0.0", pluginSettings.getUserAgent());
    }

    /** Tests that setWazuhVersion can be updated and getUserAgent reflects the latest value. */
    public void testSetWazuhVersionUpdatesUserAgent() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setVersion("4.9.0");

        Assert.assertEquals(Constants.USER_AGENT_PREFIX + "4.9.0", pluginSettings.getUserAgent());

        pluginSettings.setVersion("5.0.0");
        Assert.assertEquals(Constants.USER_AGENT_PREFIX + "5.0.0", pluginSettings.getUserAgent());
    }

    /** Tests extraction of context and consumer values from a CTI catalog consumer URL. */
    public void testCatalogUriPartsExtraction() {
        String uri = "https://cti.example/api/v1/catalog/contexts/my-context/consumers/my-consumer";

        Assert.assertEquals("my-context", PluginSettings.getContextFromCatalogUri(uri));
        Assert.assertEquals("my-consumer", PluginSettings.getConsumerFromCatalogUri(uri));
        Assert.assertEquals("", PluginSettings.getContextFromCatalogUri(""));
        Assert.assertEquals("", PluginSettings.getConsumerFromCatalogUri("invalid-uri"));
    }

    /** Tests that accessToken is null by default. */
    public void testAccessTokenIsNullByDefault() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        Assert.assertNull(pluginSettings.getAccessToken());
    }

    /** Tests that setAccessToken persists the value and getAccessToken returns it. */
    public void testSetAndGetAccessToken() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setAccessToken("test-token-abc");
        Assert.assertEquals("test-token-abc", pluginSettings.getAccessToken());
    }

    /** Tests that setAccessToken can be updated and the latest value is returned. */
    public void testAccessTokenUpdates() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setAccessToken("first-token");
        pluginSettings.setAccessToken("second-token");
        Assert.assertEquals("second-token", pluginSettings.getAccessToken());
    }

    /** Tests that setAccessToken(null) clears the token. */
    public void testAccessTokenCanBeCleared() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setAccessToken("a-token");
        pluginSettings.setAccessToken(null);
        Assert.assertNull(pluginSettings.getAccessToken());
    }

    /** Tests that isRegistered returns false when no token is set. */
    public void testIsRegisteredReturnsFalseByDefault() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        Assert.assertFalse(pluginSettings.isRegistered());
    }

    /** Tests that isRegistered returns true when a valid token is set. */
    public void testIsRegisteredReturnsTrueWithToken() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setAccessToken("some-token");
        Assert.assertTrue(pluginSettings.isRegistered());
    }

    /** Tests that isRegistered returns false after the token is cleared. */
    public void testIsRegisteredReturnsFalseAfterClear() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setAccessToken("some-token");
        pluginSettings.setAccessToken(null);
        Assert.assertFalse(pluginSettings.isRegistered());
    }

    /** Tests that isRegistered returns false when the token is blank. */
    public void testIsRegisteredReturnsFalseWithBlankToken() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setAccessToken("   ");
        Assert.assertFalse(pluginSettings.isRegistered());
    }

    /** Tests that isRegistered returns false when the token is an empty string. */
    public void testIsRegisteredReturnsFalseWithEmptyToken() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setAccessToken("");
        Assert.assertFalse(pluginSettings.isRegistered());
    }

    /** Tests that clusterUUID is null by default. */
    public void testClusterUUIDIsNullByDefault() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        Assert.assertNull(pluginSettings.getClusterUUID());
    }

    /** Tests that setClusterUUID persists the value and getClusterUUID returns it. */
    public void testSetAndGetClusterUUID() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setClusterUUID("test-cluster-uuid");
        Assert.assertEquals("test-cluster-uuid", pluginSettings.getClusterUUID());
    }

    /** Tests that setClusterUUID can be updated and the latest value is returned. */
    public void testClusterUUIDUpdates() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setClusterUUID("first-uuid");
        pluginSettings.setClusterUUID("second-uuid");
        Assert.assertEquals("second-uuid", pluginSettings.getClusterUUID());
    }

    /** Tests that setClusterUUID(null) clears the value. */
    public void testClusterUUIDCanBeCleared() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        pluginSettings.setClusterUUID("a-uuid");
        pluginSettings.setClusterUUID(null);
        Assert.assertNull(pluginSettings.getClusterUUID());
    }

    /**
     * Both catalog scheduling settings must be dynamic, otherwise the cluster settings API rejects an
     * update to them and the operator is back to editing opensearch.yml and restarting.
     */
    public void testCatalogSchedulingSettingsAreDynamic() {
        Assert.assertTrue(
                "update_on_schedule must be dynamic", PluginSettings.UPDATE_ON_SCHEDULE.isDynamic());
        Assert.assertTrue(
                "sync_interval must be dynamic", PluginSettings.CATALOG_SYNC_INTERVAL.isDynamic());
    }

    /** The scheduled-update setter must be readable back through its getter. */
    public void testSetAndIsUpdateOnSchedule() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        boolean original = pluginSettings.isUpdateOnSchedule();
        try {
            pluginSettings.setUpdateOnSchedule(false);
            Assert.assertFalse(pluginSettings.isUpdateOnSchedule());
            pluginSettings.setUpdateOnSchedule(true);
            Assert.assertTrue(pluginSettings.isUpdateOnSchedule());
        } finally {
            pluginSettings.setUpdateOnSchedule(original);
        }
    }

    /** The sync interval setter must be readable back through its getter. */
    public void testSetAndGetCatalogSyncInterval() {
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);
        int original = pluginSettings.getCatalogSyncInterval();
        try {
            pluginSettings.setCatalogSyncInterval(120);
            Assert.assertEquals(Integer.valueOf(120), pluginSettings.getCatalogSyncInterval());
        } finally {
            pluginSettings.setCatalogSyncInterval(original);
        }
    }

    /**
     * The central guarantee of the constants-to-settings migration: every promoted setting defaults
     * to exactly the value that used to be compiled in, so an untouched opensearch.yml behaves as the
     * previous release did. The literals below are the constants as they stood before the promotion;
     * they are written out rather than referenced so that changing a default in PluginSettings cannot
     * silently satisfy this test.
     */
    public void testPromotedDefaultsMatchPreviousHardcodedValues() {
        PluginSettings s = PluginSettings.getInstance(Settings.EMPTY);

        // ContentIndex.RetryPolicy.SHED(3, 1_000, 30_000)
        Assert.assertEquals(3, s.getBulkShedMaxRetries());
        Assert.assertEquals(1_000L, s.getBulkShedInitialBackoffMillis());
        Assert.assertEquals(30_000L, s.getBulkShedMaxBackoffMillis());
        // ContentIndex.RetryPolicy.TOPOLOGY(5, 5_000, 30_000)
        Assert.assertEquals(5, s.getBulkTopologyMaxRetries());
        Assert.assertEquals(5_000L, s.getBulkTopologyInitialBackoffMillis());
        Assert.assertEquals(30_000L, s.getBulkTopologyMaxBackoffMillis());
        // Constants.MAX_JOB_SCHEDULE_RETRIES / JOB_SCHEDULE_RETRY_BACKOFF_SECONDS
        Assert.assertEquals(3, s.getJobScheduleMaxRetries());
        Assert.assertEquals(15, s.getJobScheduleRetryBackoffSeconds());
        // Constants.MAX_LOCK_ACQUIRE_RETRIES / LOCK_ACQUIRE_RETRY_BACKOFF_MILLIS /
        // LOCK_STALE_THRESHOLD_MILLIS
        Assert.assertEquals(20, s.getResourceLockMaxRetries());
        Assert.assertEquals(100L, s.getResourceLockRetryBackoffMillis());
        Assert.assertEquals(30_000L, s.getResourceLockStaleThresholdMillis());
        // Constants.MAX_USER_OVERRIDES_UPDATE_ATTEMPTS / IntegrationService.MAX_RETRIES
        Assert.assertEquals(3, s.getUserOverridesMaxUpdateAttempts());
        Assert.assertEquals(5, s.getIntegrationMaxUpdateAttempts());
        // cti.console.client.ApiClient BASE_URI / TIMEOUT
        Assert.assertEquals("https://api.pre.cloud.wazuh.com", s.getCtiConsoleUrl());
        Assert.assertEquals(5, s.getCtiRequestTimeout());
        // EngineContentLoader RELOAD_TIMEOUT / NOT_READY_GRACE, EngineSocketClient socket path
        Assert.assertEquals(10, s.getEngineReloadTimeoutMinutes());
        Assert.assertEquals(5, s.getEngineNotReadyGraceMinutes());
        Assert.assertEquals(
                "/usr/share/wazuh-indexer/engine/sockets/engine-api-http.sock", s.getEngineSocketPath());
        // ConsumerRulesetService latch waits, SecurityAnalyticsServiceImpl DEFAULT_INTERVAL
        Assert.assertEquals(60, s.getSaSyncTimeoutSeconds());
        Assert.assertEquals(30, s.getSaDetectorTimeoutSeconds());
        Assert.assertEquals(120, s.getSaCleanupTimeoutSeconds());
        Assert.assertEquals(2, s.getSaDetectorInterval());
        // ContentIndex.UPDATE_SUB_BATCH_SIZE, FLUSH_EVERY_N_BATCHES / FLUSH_EVERY_N_BULKS,
        // DetectorLookupService.MAX_RESULTS / ConsumerIocService.SEARCH_PAGE_SIZE
        Assert.assertEquals(50, s.getUpdateSubBatchSize());
        Assert.assertEquals(10, s.getOffsetFlushInterval());
        Assert.assertEquals(10_000, s.getSearchPageSize());
    }

    /**
     * The bulk retry budgets are the knob an operator reaches for mid-incident, so they must be
     * updatable through the cluster settings API rather than only through opensearch.yml.
     */
    public void testBulkRetrySettingsAreDynamic() {
        Assert.assertTrue(PluginSettings.BULK_SHED_MAX_RETRIES.isDynamic());
        Assert.assertTrue(PluginSettings.BULK_SHED_INITIAL_BACKOFF_MILLIS.isDynamic());
        Assert.assertTrue(PluginSettings.BULK_SHED_MAX_BACKOFF_MILLIS.isDynamic());
        Assert.assertTrue(PluginSettings.BULK_TOPOLOGY_MAX_RETRIES.isDynamic());
        Assert.assertTrue(PluginSettings.BULK_TOPOLOGY_INITIAL_BACKOFF_MILLIS.isDynamic());
        Assert.assertTrue(PluginSettings.BULK_TOPOLOGY_MAX_BACKOFF_MILLIS.isDynamic());
        Assert.assertTrue(PluginSettings.RESOURCE_LOCK_MAX_RETRIES.isDynamic());
        Assert.assertTrue(PluginSettings.RESOURCE_LOCK_RETRY_BACKOFF_MILLIS.isDynamic());
        Assert.assertTrue(PluginSettings.RESOURCE_LOCK_STALE_THRESHOLD_MILLIS.isDynamic());
        Assert.assertTrue(PluginSettings.USER_OVERRIDES_MAX_UPDATE_ATTEMPTS.isDynamic());
        Assert.assertTrue(PluginSettings.INTEGRATION_MAX_UPDATE_ATTEMPTS.isDynamic());
        Assert.assertTrue(PluginSettings.SA_DETECTOR_INTERVAL.isDynamic());
    }

    /** Values supplied in the node configuration must win over the defaults. */
    public void testPromotedSettingsReadCustomValues() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.bulk.retry.topology.max_retries", 12)
                        .put("plugins.content_manager.bulk.retry.topology.initial_backoff_millis", 10_000L)
                        .put("plugins.content_manager.cti.console.api", "https://api.cloud.wazuh.com")
                        .put("plugins.content_manager.cti.console.timeout", 30)
                        .put("plugins.content_manager.engine.socket_path", "/tmp/engine.sock")
                        .put("plugins.content_manager.search_page_size", 500)
                        .put("plugins.content_manager.offset_flush_interval", 1)
                        .build();
        PluginSettings s = PluginSettings.getInstance(settings);

        Assert.assertEquals(12, s.getBulkTopologyMaxRetries());
        Assert.assertEquals(10_000L, s.getBulkTopologyInitialBackoffMillis());
        Assert.assertEquals("https://api.cloud.wazuh.com", s.getCtiConsoleUrl());
        Assert.assertEquals(30, s.getCtiRequestTimeout());
        Assert.assertEquals("/tmp/engine.sock", s.getEngineSocketPath());
        Assert.assertEquals(500, s.getSearchPageSize());
        Assert.assertEquals(1, s.getOffsetFlushInterval());
    }

    /** A retry budget below its minimum is rejected rather than silently clamped. */
    public void testBulkRetriesBelowMinThrows() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.bulk.retry.shed.max_retries", -1).build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /** A retry budget above its maximum is rejected, so a typo cannot produce an endless loop. */
    public void testBulkRetriesAboveMaxThrows() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.bulk.retry.shed.max_retries", 21).build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /** A page size above the OpenSearch index.max_result_window default is rejected. */
    public void testSearchPageSizeAboveMaxThrows() {
        Settings settings =
                Settings.builder().put("plugins.content_manager.search_page_size", 10_001).build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(settings));
    }

    /**
     * A detector interval outside the bounds Security Analytics accepts is rejected at configuration
     * time rather than producing detectors the plugin will refuse.
     */
    public void testDetectorIntervalOutOfBoundsThrows() {
        Settings tooSmall =
                Settings.builder()
                        .put(
                                "plugins.content_manager.security_analytics.detector_interval",
                                Constants.DETECTOR_INTERVAL_MIN_MINUTES - 1)
                        .build();
        Assert.assertThrows(IllegalArgumentException.class, () -> PluginSettings.getInstance(tooSmall));
    }

    /** The dynamic retry-budget setters must be readable back through their getters. */
    public void testSetAndGetBulkRetryBudgets() {
        PluginSettings s = PluginSettings.getInstance(Settings.EMPTY);

        s.setBulkShedMaxRetries(7);
        s.setBulkShedInitialBackoffMillis(2_500L);
        s.setBulkShedMaxBackoffMillis(45_000L);
        s.setBulkTopologyMaxRetries(9);
        s.setBulkTopologyInitialBackoffMillis(7_500L);
        s.setBulkTopologyMaxBackoffMillis(60_000L);

        Assert.assertEquals(7, s.getBulkShedMaxRetries());
        Assert.assertEquals(2_500L, s.getBulkShedInitialBackoffMillis());
        Assert.assertEquals(45_000L, s.getBulkShedMaxBackoffMillis());
        Assert.assertEquals(9, s.getBulkTopologyMaxRetries());
        Assert.assertEquals(7_500L, s.getBulkTopologyInitialBackoffMillis());
        Assert.assertEquals(60_000L, s.getBulkTopologyMaxBackoffMillis());
    }

    /**
     * The promoted settings are tuning knobs, not secrets, and must stay readable through the cluster
     * settings API.
     *
     * <p>{@code Setting.Property.Filtered} is not a display hint: {@code
     * SettingsFilter#filterSettings} calls {@code builder.remove(pattern)}, and {@code
     * RestClusterGetSettingsAction} applies that filter to the {@code include_defaults} branch too,
     * so a filtered setting disappears from {@code GET _cluster/settings?include_defaults=true}
     * entirely. It also suppresses the offending value in validation errors — {@code Setting} builds
     * them as {@code "Failed to parse value" + (isFiltered() ? "" : " [" + value + "]")} — so an
     * operator who fat-fingers a page size is told only that the setting is wrong, not what they
     * typed. Neither is acceptable for a page size, a batch size or a socket path.
     */
    public void testPromotedSettingsAreNotFiltered() {
        Setting<?>[] promoted = {
            PluginSettings.BULK_SHED_MAX_RETRIES,
            PluginSettings.BULK_SHED_INITIAL_BACKOFF_MILLIS,
            PluginSettings.BULK_SHED_MAX_BACKOFF_MILLIS,
            PluginSettings.BULK_TOPOLOGY_MAX_RETRIES,
            PluginSettings.BULK_TOPOLOGY_INITIAL_BACKOFF_MILLIS,
            PluginSettings.BULK_TOPOLOGY_MAX_BACKOFF_MILLIS,
            PluginSettings.JOB_SCHEDULE_MAX_RETRIES,
            PluginSettings.JOB_SCHEDULE_RETRY_BACKOFF_SECONDS,
            PluginSettings.RESOURCE_LOCK_MAX_RETRIES,
            PluginSettings.RESOURCE_LOCK_RETRY_BACKOFF_MILLIS,
            PluginSettings.RESOURCE_LOCK_STALE_THRESHOLD_MILLIS,
            PluginSettings.USER_OVERRIDES_MAX_UPDATE_ATTEMPTS,
            PluginSettings.INTEGRATION_MAX_UPDATE_ATTEMPTS,
            PluginSettings.CTI_CONSOLE_URL,
            PluginSettings.CTI_API_TIMEOUT,
            PluginSettings.ENGINE_RELOAD_TIMEOUT_MINUTES,
            PluginSettings.ENGINE_NOT_READY_GRACE_MINUTES,
            PluginSettings.ENGINE_SOCKET_PATH,
            PluginSettings.SA_SYNC_TIMEOUT_SECONDS,
            PluginSettings.SA_DETECTOR_TIMEOUT_SECONDS,
            PluginSettings.SA_CLEANUP_TIMEOUT_SECONDS,
            PluginSettings.SA_DETECTOR_INTERVAL,
            PluginSettings.UPDATE_SUB_BATCH_SIZE,
            PluginSettings.OFFSET_FLUSH_INTERVAL,
            PluginSettings.SEARCH_PAGE_SIZE,
        };
        for (Setting<?> setting : promoted) {
            Assert.assertFalse(
                    setting.getKey() + " must stay visible in GET _cluster/settings", setting.isFiltered());
        }
    }
}
