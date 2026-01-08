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
package com.wazuh.contentmanager.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

import reactor.util.annotation.NonNull;

/**
 * Encapsulates configuration settings and constants for the Content Manager plugin. This class
 * provides a centralized location for managing plugin configuration values, including CTI API
 * endpoints, bulk operation limits, timeout values, and synchronization intervals.
 */
public class PluginSettings {
    /** Logger instance for the PluginSettings class. */
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    /** Base URI for all Content Manager plugin REST API endpoints. */
    public static final String PLUGINS_BASE_URI = "/_plugins/content-manager";

    /** URI endpoint for subscription-related operations. */
    public static final String SUBSCRIPTION_URI = PLUGINS_BASE_URI + "/subscription";

    /** URI endpoint for update-related operations. */
    public static final String UPDATE_URI = PLUGINS_BASE_URI + "/update";

    /** Default maximum number of items to include in a single bulk request. */
    private static final int DEFAULT_MAX_ITEMS_PER_BULK = 25;

    private static final int DEFAULT_MAX_CONCURRENT_BULKS = 5;
    private static final int DEFAULT_CLIENT_TIMEOUT = 10;
    private static final int DEFAULT_CATALOG_SYNC_INTERVAL = 60;

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /** Base Wazuh CTI URL */
    public static final String CTI_URL = "https://cti-pre.wazuh.com";

    /** The CTI API URL from the configuration file */
    public static final Setting<String> CTI_API_URL =
            Setting.simpleString(
                    "content_manager.cti.api",
                    CTI_URL + "/api/v1",
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * OpenSearch setting for the maximum number of elements included in a single bulk request during
     * initialization from a snapshot. This setting controls bulk operation size to balance
     * performance and resource usage. Valid range is 10-25 items, with a default of 25.
     */
    public static final Setting<Integer> MAX_ITEMS_PER_BULK =
            Setting.intSetting(
                    "content_manager.max_items_per_bulk",
                    DEFAULT_MAX_ITEMS_PER_BULK,
                    10,
                    25,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * OpenSearch setting for the maximum number of concurrent bulk operations allowed during
     * initialization from a snapshot. This setting limits parallelism to prevent resource exhaustion.
     * Valid range is 1-5 concurrent operations, with a default of 5.
     */
    public static final Setting<Integer> MAX_CONCURRENT_BULKS =
            Setting.intSetting(
                    "content_manager.max_concurrent_bulks",
                    DEFAULT_MAX_CONCURRENT_BULKS,
                    1,
                    5,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * OpenSearch setting for the timeout duration in seconds for indexing operations. This setting
     * defines how long the client will wait for indexing requests to complete before timing out.
     * Valid range is 10-50 seconds, with a default of 10 seconds.
     */
    public static final Setting<Long> CLIENT_TIMEOUT =
            Setting.longSetting(
                    "content_manager.client.timeout",
                    DEFAULT_CLIENT_TIMEOUT,
                    10,
                    50,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * OpenSearch setting for the catalog synchronization job interval in minutes. This setting
     * controls how frequently the plugin synchronizes with the CTI catalog to fetch updates. Valid
     * range is 1-1440 minutes (1 day), with a default of 60 minutes.
     */
    public static final Setting<Integer> CATALOG_SYNC_INTERVAL =
            Setting.intSetting(
                    "content_manager.catalog.sync_interval",
                    DEFAULT_CATALOG_SYNC_INTERVAL,
                    1,
                    1440,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The configured base URL for the CTI API. */
    private final String ctiBaseUrl;

    /** The configured maximum number of items per bulk request. */
    private final int maximumItemsPerBulk;

    /** The configured maximum number of concurrent bulk operations. */
    private final int maximumConcurrentBulks;

    /** The configured client timeout in seconds for indexing operations. */
    private final long clientTimeout;

    /** The configured catalog synchronization interval in minutes. */
    private final int catalogSyncInterval;

    /**
     * Private constructor to initialize plugin settings from OpenSearch cluster configuration. This
     * constructor extracts all configured values from the provided settings object and caches them as
     * instance fields for efficient access.
     *
     * @param settings The OpenSearch Settings object containing cluster configuration, typically
     *     obtained during plugin component creation.
     */
    private PluginSettings(@NonNull final Settings settings) {
        this.ctiBaseUrl = CTI_API_URL.get(settings);
        this.maximumItemsPerBulk = MAX_ITEMS_PER_BULK.get(settings);
        this.maximumConcurrentBulks = MAX_CONCURRENT_BULKS.get(settings);
        this.clientTimeout = CLIENT_TIMEOUT.get(settings);
        this.catalogSyncInterval = CATALOG_SYNC_INTERVAL.get(settings);
        log.debug("Settings.loaded: {}", this.toString());
    }

    /**
     * Retrieves or initializes the singleton instance of PluginSettings. This method performs lazy
     * initialization, creating the instance on first access using the provided cluster settings.
     *
     * @param settings The OpenSearch Settings object containing cluster configuration, typically
     *     obtained during plugin component creation.
     * @return The singleton PluginSettings instance.
     */
    public static synchronized PluginSettings getInstance(@NonNull final Settings settings) {
        if (INSTANCE == null) {
            INSTANCE = new PluginSettings(settings);
        }
        return INSTANCE;
    }

    /**
     * Retrieves the singleton instance of PluginSettings. This method should only be called after the
     * instance has been initialized via {@link #getInstance(Settings)}.
     *
     * @return The singleton PluginSettings instance.
     * @throws IllegalStateException If the instance has not been initialized with settings.
     * @see #getInstance(Settings)
     */
    public static synchronized PluginSettings getInstance() {
        if (PluginSettings.INSTANCE == null) {
            throw new IllegalStateException("Plugin settings have not been initialized.");
        }
        return INSTANCE;
    }

    /**
     * Retrieves the configured base URL for the Cyber Threat Intelligence (CTI) API.
     *
     * @return The CTI API base URL string.
     */
    public String getCtiBaseUrl() {
        return this.ctiBaseUrl;
    }

    /**
     * Retrieves the configured maximum number of documents that can be included in a single bulk
     * request during content indexing operations.
     *
     * @return The maximum number of items per bulk request (10-25).
     */
    public Integer getMaxItemsPerBulk() {
        return this.maximumItemsPerBulk;
    }

    /**
     * Retrieves the configured maximum number of concurrent bulk operations allowed during content
     * indexing.
     *
     * @return The maximum number of concurrent bulk operations (1-5).
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
     * Returns a string representation of the plugin settings, including all configured values. This
     * method is primarily used for debugging and logging purposes.
     *
     * @return A JSON-like string containing all plugin setting values.
     */
    @Override
    public String toString() {
        return "{"
                + "ctiBaseUrl='"
                + this.ctiBaseUrl
                + "', "
                + "maximumItemsPerBulk="
                + this.maximumItemsPerBulk
                + ", "
                + "maximumConcurrentBulks="
                + this.maximumConcurrentBulks
                + ", "
                + "clientTimeout="
                + this.clientTimeout
                + ", "
                + "catalogSyncInterval="
                + this.catalogSyncInterval
                + "}";
    }
}
