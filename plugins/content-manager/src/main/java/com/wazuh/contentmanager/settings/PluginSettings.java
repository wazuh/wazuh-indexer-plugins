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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.wazuh.contentmanager.utils.Constants;
import org.jspecify.annotations.NonNull;

/** This class encapsulates configuration settings and constants for the Content Manager plugin. */
public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    // Rest API endpoints
    public static final String PLUGINS_BASE_URI = "/_plugins/_content_manager";
    public static final String SUBSCRIPTION_URI = PLUGINS_BASE_URI + "/subscription";
    public static final String UPDATE_URI = PLUGINS_BASE_URI + "/update";
    public static final String LOGTEST_URI = PLUGINS_BASE_URI + "/logtest";
    public static final String LOGTEST_NORMALIZATION_URI = LOGTEST_URI + "/normalization";
    public static final String LOGTEST_DETECTION_URI = LOGTEST_URI + "/detection";
    public static final String KVDBS_URI = PLUGINS_BASE_URI + "/kvdbs";
    public static final String DECODERS_URI = PLUGINS_BASE_URI + "/decoders";
    public static final String RULES_URI = PLUGINS_BASE_URI + "/rules";
    public static final String INTEGRATIONS_URI = PLUGINS_BASE_URI + "/integrations";
    public static final String PROMOTE_URI = PLUGINS_BASE_URI + "/promote";
    public static final String POLICY_URI = PLUGINS_BASE_URI + "/policy";
    public static final String FILTERS_URI = PLUGINS_BASE_URI + "/filters";
    public static final String SPACE_URI = PLUGINS_BASE_URI + "/space";
    public static final String VERSION_CHECK_URI = PLUGINS_BASE_URI + "/version/check";

    /** Settings default values */
    private static final int DEFAULT_MAX_ITEMS_PER_BULK = 999;

    private static final long DEFAULT_MAX_BULK_BYTES = 5L * 1024 * 1024;
    private static final int DEFAULT_MAX_CONCURRENT_BULKS = 5;
    private static final int DEFAULT_CLIENT_TIMEOUT = 10;
    private static final int DEFAULT_CATALOG_SYNC_INTERVAL = 60;
    private static final boolean DEFAULT_UPDATE_ON_START = true;
    private static final boolean DEFAULT_UPDATE_ON_SCHEDULE = true;
    private static final boolean DEFAULT_CREATE_DETECTORS = true;

    // Default values for catalog consumer URLs
    private static final String DEFAULT_CATALOG_RULESET = "";
    private static final String DEFAULT_CATALOG_IOCS = "";
    private static final String DEFAULT_CATALOG_VULNERABILITIES = "";

    private static final long DEFAULT_PIT_KEEPALIVE = 120;
    private static final boolean DEFAULT_ENGINE_MOCK_ENABLED = false;

    private static final Pattern CATALOG_URI_PATTERN =
            Pattern.compile(".*/catalog/contexts/([^/]+)/consumers/([^/?#]+)(?:[/?#].*)?$");

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /** Base Wazuh CTI URL */
    public static final String CTI_URL = "https://api.pre.cloud.wazuh.com/api/v1";

    /** The CTI API URL from the configuration file */
    public static final Setting<String> CTI_API_URL =
            Setting.simpleString(
                    "plugins.content_manager.cti.api",
                    CTI_URL,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * The maximum number of elements that are included in a bulk request during the initialization
     * from a snapshot.
     */
    public static final Setting<Integer> MAX_ITEMS_PER_BULK =
            Setting.intSetting(
                    "plugins.content_manager.max_items_per_bulk",
                    DEFAULT_MAX_ITEMS_PER_BULK,
                    10,
                    999,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * The maximum estimated size, in bytes, of an accumulated bulk request before it is flushed
     * during the initialization from a snapshot. Bounds peak heap regardless of individual document
     * size (e.g. large CVE documents): worst-case in-flight payload is {@code MAX_CONCURRENT_BULKS *
     * MAX_BULK_BYTES}. The 100 MB ceiling stays under the OpenSearch default {@code
     * http.max_content_length}.
     */
    public static final Setting<Long> MAX_BULK_BYTES =
            Setting.longSetting(
                    "plugins.content_manager.max_bulk_bytes",
                    DEFAULT_MAX_BULK_BYTES,
                    1L * 1024 * 1024,
                    100L * 1024 * 1024,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * The maximum number of co-existing bulk operations during the initialization from a snapshot.
     */
    public static final Setting<Integer> MAX_CONCURRENT_BULKS =
            Setting.intSetting(
                    "plugins.content_manager.max_concurrent_bulks",
                    DEFAULT_MAX_CONCURRENT_BULKS,
                    1,
                    5,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Timeout of indexing operations */
    public static final Setting<Long> CLIENT_TIMEOUT =
            Setting.longSetting(
                    "plugins.content_manager.client.timeout",
                    DEFAULT_CLIENT_TIMEOUT,
                    10,
                    50,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The interval in minutes for the catalog synchronization job. */
    public static final Setting<Integer> CATALOG_SYNC_INTERVAL =
            Setting.intSetting(
                    "plugins.content_manager.catalog.sync_interval",
                    DEFAULT_CATALOG_SYNC_INTERVAL,
                    10,
                    1440,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Setting to trigger content update on start. */
    public static final Setting<Boolean> UPDATE_ON_START =
            Setting.boolSetting(
                    "plugins.content_manager.catalog.update_on_start",
                    DEFAULT_UPDATE_ON_START,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Setting to enable/disable the content update job. */
    public static final Setting<Boolean> UPDATE_ON_SCHEDULE =
            Setting.boolSetting(
                    "plugins.content_manager.catalog.update_on_schedule",
                    DEFAULT_UPDATE_ON_SCHEDULE,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Setting to enable/disable the content update job. */
    public static final Setting<Boolean> CREATE_DETECTORS =
            Setting.boolSetting(
                    "plugins.content_manager.catalog.create_detectors",
                    DEFAULT_CREATE_DETECTORS,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Full ruleset catalog consumer URL. */
    public static final Setting<String> CATALOG_RULESET =
            Setting.simpleString(
                    "plugins.content_manager.catalog.ruleset",
                    DEFAULT_CATALOG_RULESET,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Full IoCs catalog consumer URL. */
    public static final Setting<String> CATALOG_IOCS =
            Setting.simpleString(
                    "plugins.content_manager.catalog.iocs",
                    DEFAULT_CATALOG_IOCS,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Full vulnerabilities catalog consumer URL. */
    public static final Setting<String> CATALOG_VULNERABILITIES =
            Setting.simpleString(
                    "plugins.content_manager.catalog.vulnerabilities",
                    DEFAULT_CATALOG_VULNERABILITIES,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** PIT (Point-in-Time) keepalive duration in seconds for paginated searches. */
    public static final Setting<Long> PIT_KEEPALIVE =
            Setting.longSetting(
                    "plugins.content_manager.pit_keepalive",
                    DEFAULT_PIT_KEEPALIVE,
                    60,
                    600,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Setting to enable mock engine service for testing environments. */
    public static final Setting<Boolean> ENGINE_MOCK_ENABLED =
            Setting.boolSetting(
                    "plugins.content_manager.engine.mock",
                    DEFAULT_ENGINE_MOCK_ENABLED,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Configuration setting to enable or disable the telemetry ping. Defaults to true. */
    public static final Setting<Boolean> TELEMETRY_ENABLED =
            Setting.boolSetting(
                    "plugins.content_manager.telemetry.enabled",
                    true,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    private final String ctiBaseUrl;
    private final int maximumItemsPerBulk;
    private final long maximumBulkBytes;
    private final int maximumConcurrentBulks;
    private final long clientTimeout;
    private final int catalogSyncInterval;
    private final boolean updateOnStart;
    private final boolean updateOnSchedule;
    private final String catalogRuleset;
    private final String catalogIocs;
    private final String catalogVulnerabilities;
    private final long pitKeepalive;
    private final boolean engineMockEnabled;
    private final boolean createDetectors;
    private volatile boolean isTelemetryEnabled;
    private volatile String accessToken;
    private String version;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings) {
        this.ctiBaseUrl = CTI_API_URL.get(settings);
        this.maximumItemsPerBulk = MAX_ITEMS_PER_BULK.get(settings);
        this.maximumBulkBytes = MAX_BULK_BYTES.get(settings);
        this.maximumConcurrentBulks = MAX_CONCURRENT_BULKS.get(settings);
        this.clientTimeout = CLIENT_TIMEOUT.get(settings);
        this.catalogSyncInterval = CATALOG_SYNC_INTERVAL.get(settings);
        this.updateOnStart = UPDATE_ON_START.get(settings);
        this.updateOnSchedule = UPDATE_ON_SCHEDULE.get(settings);
        this.catalogRuleset = CATALOG_RULESET.get(settings);
        this.catalogIocs = CATALOG_IOCS.get(settings);
        this.catalogVulnerabilities = CATALOG_VULNERABILITIES.get(settings);
        this.pitKeepalive = PIT_KEEPALIVE.get(settings);
        this.engineMockEnabled = ENGINE_MOCK_ENABLED.get(settings);
        this.createDetectors = CREATE_DETECTORS.get(settings);
        this.isTelemetryEnabled = TELEMETRY_ENABLED.get(settings);
        log.debug("Settings.loaded: {}", this.toString());
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @param settings as obtained in createComponents.
     * @return {@link PluginSettings#INSTANCE}
     */
    public static synchronized PluginSettings getInstance(@NonNull final Settings settings) {
        if (INSTANCE == null) {
            INSTANCE = new PluginSettings(settings);
        }
        return INSTANCE;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#INSTANCE}
     * @throws IllegalStateException if the instance has not been initialized
     * @see PluginSettings#getInstance(Settings)
     */
    public static synchronized PluginSettings getInstance() {
        if (PluginSettings.INSTANCE == null) {
            throw new IllegalStateException("Plugin settings have not been initialized.");
        }
        return INSTANCE;
    }

    /**
     * Resets the singleton instance. Intended for use in unit tests only.
     *
     * <p><strong>WARNING:</strong> Do not call this method in production code.
     */
    public static synchronized void resetForTesting() {
        INSTANCE = null;
    }

    public void setTelemetryEnabled(boolean isTelemetryEnabled) {
        this.isTelemetryEnabled = isTelemetryEnabled;
    }

    /**
     * Sets the CTI access token.
     *
     * @param accessToken the access token string, or null to clear it.
     */
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * Retrieves the CTI access token.
     *
     * @return the access token string, or null if not set.
     */
    public String getAccessToken() {
        return this.accessToken;
    }

    /**
     * Returns whether this instance is registered in the Wazuh CTI Platform. A registered instance
     * has a non-null, non-blank access token.
     *
     * @return true if the instance is registered, false otherwise.
     */
    public boolean isRegistered() {
        return this.accessToken != null && !this.accessToken.isBlank();
    }

    /**
     * Sets the version of Wazuh. Should be called once during plugin initialization.
     *
     * @param version the Wazuh version string (e.g., "5.0.0").
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Retrieves the version of Wazuh.
     *
     * @return the Wazuh version string, or null if not set.
     */
    public String getVersion() {
        return this.version;
    }

    /**
     * Builds the custom user-agent string for CTI API communications.
     *
     * @return the user-agent string in the format "Wazuh Indexer {version}".
     */
    public String getUserAgent() {
        String version = this.version != null ? this.version : "unknown";
        return Constants.USER_AGENT_PREFIX + version;
    }

    /**
     * Getter method for the CTI API URL
     *
     * @return a string with the base URL
     */
    public String getCtiBaseUrl() {
        return this.ctiBaseUrl;
    }

    /**
     * Retrieves the maximum number of documents that can be indexed.
     *
     * @return an Integer representing the maximum number of documents allowed for content indexing.
     */
    public Integer getMaxItemsPerBulk() {
        return this.maximumItemsPerBulk;
    }

    /**
     * Retrieves the maximum estimated size, in bytes, of an accumulated bulk request before it is
     * flushed during snapshot indexing.
     *
     * @return a long representing the maximum bulk request size in bytes.
     */
    public long getMaxBulkBytes() {
        return this.maximumBulkBytes;
    }

    /**
     * Retrieves the maximum number of concurrent petitions allowed for content indexing.
     *
     * @return an Integer representing the maximum number of concurrent petitions.
     */
    public Integer getMaximumConcurrentBulks() {
        return this.maximumConcurrentBulks;
    }

    /**
     * Retrieves the timeout value for content and context indexing operations.
     *
     * @return a Long representing the timeout duration in seconds.
     */
    public Long getClientTimeout() {
        return this.clientTimeout;
    }

    /**
     * Retrieves the interval in minutes for the catalog synchronization job.
     *
     * @return an Integer representing the interval in minutes.
     */
    public Integer getCatalogSyncInterval() {
        return this.catalogSyncInterval;
    }

    /**
     * Retrieves the value for the update on start setting.
     *
     * @return a Boolean indicating if the update on start is enabled.
     */
    public Boolean isUpdateOnStart() {
        return this.updateOnStart;
    }

    /**
     * Retrieves the value for the update on schedule setting.
     *
     * @return a Boolean indicating if the scheduled update is enabled.
     */
    public Boolean isUpdateOnSchedule() {
        return this.updateOnSchedule;
    }

    /**
     * Retrieves the value for the update on schedule setting.
     *
     * @return a Boolean indicating if the scheduled update is enabled.
     */
    public Boolean isTelemetryEnabled() {
        return this.isTelemetryEnabled;
    }

    /** Retrieves the full ruleset catalog consumer URL. */
    public String getCatalogRuleset() {
        return this.catalogRuleset;
    }

    /**
     * Retrieves the Content Consumer.
     *
     * @return the consumer string.
     */
    public boolean getCreateDetectors() {
        return this.createDetectors;
    }

    /** Retrieves the full IoCs catalog consumer URL. */
    public String getCatalogIocs() {
        return this.catalogIocs;
    }

    /** Retrieves the full vulnerabilities catalog consumer URL. */
    public String getCatalogVulnerabilities() {
        return this.catalogVulnerabilities;
    }

    /**
     * Extracts the context segment from a consumer URL.
     *
     * @param catalogUri full consumer URL.
     * @return context value, or an empty string when the URL does not match the expected format.
     */
    public static String getContextFromCatalogUri(String catalogUri) {
        return PluginSettings.getCatalogUriPart(catalogUri, 1);
    }

    /**
     * Extracts the consumer segment from a consumer URL.
     *
     * @param catalogUri full consumer URL.
     * @return consumer value, or an empty string when the URL does not match the expected format.
     */
    public static String getConsumerFromCatalogUri(String catalogUri) {
        return PluginSettings.getCatalogUriPart(catalogUri, 2);
    }

    private static String getCatalogUriPart(String catalogUri, int group) {
        if (catalogUri == null || catalogUri.isBlank()) {
            return "";
        }

        Matcher matcher = CATALOG_URI_PATTERN.matcher(catalogUri);
        if (matcher.matches()) {
            return matcher.group(group);
        }

        return "";
    }

    /**
     * Retrieves the PIT (Point-in-Time) keepalive duration in seconds.
     *
     * @return the keepalive duration in seconds.
     */
    public Long getPitKeepalive() {
        return this.pitKeepalive;
    }

    /**
     * Retrieves the value for the engine mock enabled setting.
     *
     * @return a Boolean indicating if the mock engine service is enabled.
     */
    public Boolean isEngineMockEnabled() {
        return this.engineMockEnabled;
    }

    @Override
    public String toString() {
        return "{"
                + "ctiBaseUrl='"
                + this.ctiBaseUrl
                + "', "
                + "maximumItemsPerBulk="
                + this.maximumItemsPerBulk
                + ", "
                + "maximumBulkBytes="
                + this.maximumBulkBytes
                + ", "
                + "maximumConcurrentBulks="
                + this.maximumConcurrentBulks
                + ", "
                + "clientTimeout="
                + this.clientTimeout
                + ", "
                + "catalogSyncInterval="
                + this.catalogSyncInterval
                + ", "
                + "updateOnStart="
                + this.updateOnStart
                + ", "
                + "updateOnSchedule="
                + this.updateOnSchedule
                + ", "
                + "catalogRuleset='"
                + this.catalogRuleset
                + "', "
                + "catalogIocs='"
                + this.catalogIocs
                + "', "
                + "catalogVulnerabilities='"
                + this.catalogVulnerabilities
                + "'}";
    }
}
