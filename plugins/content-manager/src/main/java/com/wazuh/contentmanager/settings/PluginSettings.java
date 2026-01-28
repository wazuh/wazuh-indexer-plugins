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

import reactor.util.annotation.NonNull;

/** This class encapsulates configuration settings and constants for the Content Manager plugin. */
public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    // Rest API endpoints
    public static final String PLUGINS_BASE_URI = "/_plugins/_content_manager";
    public static final String SUBSCRIPTION_URI = PLUGINS_BASE_URI + "/subscription";
    public static final String UPDATE_URI = PLUGINS_BASE_URI + "/update";
    public static final String LOGTEST_URI = PLUGINS_BASE_URI + "/logtest";
    public static final String KVDBS_URI = PLUGINS_BASE_URI + "/kvdbs";
    public static final String DECODERS_URI = PLUGINS_BASE_URI + "/decoders";
    public static final String RULES_URI = PLUGINS_BASE_URI + "/rules";
    public static final String INTEGRATIONS_URI = PLUGINS_BASE_URI + "/integrations";
    public static final String PROMOTE_URI = PLUGINS_BASE_URI + "/promote";
    public static final String PROMOTE_PREVIEW_URI = PLUGINS_BASE_URI + "/promote_preview";

    /** Settings default values */
    private static final int DEFAULT_MAX_ITEMS_PER_BULK = 25;

    private static final int DEFAULT_MAX_CONCURRENT_BULKS = 5;
    private static final int DEFAULT_CLIENT_TIMEOUT = 10;
    private static final int DEFAULT_CATALOG_SYNC_INTERVAL = 60;
    private static final boolean DEFAULT_UPDATE_ON_START = true;
    private static final boolean DEFAULT_UPDATE_ON_SCHEDULE = true;

    // Default values for Context and Consumer
    private static final String DEFAULT_CONTENT_CONTEXT = "development_0.0.3";
    private static final String DEFAULT_CONTENT_CONSUMER = "development_0.0.3_test";

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /** Base Wazuh CTI URL */
    public static final String CTI_URL = "https://cti-pre.wazuh.com";

    /** The CTI API URL from the configuration file */
    public static final Setting<String> CTI_API_URL =
            Setting.simpleString(
                    "plugins.content_manager.cti.api",
                    CTI_URL + "/api/v1",
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
                    25,
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
                    1,
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

    /** Unified Context for Content. */
    public static final Setting<String> CONTENT_CONTEXT =
            Setting.simpleString(
                    "plugins.content_manager.catalog.content.context",
                    DEFAULT_CONTENT_CONTEXT,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Unified Consumer for Content. */
    public static final Setting<String> CONTENT_CONSUMER =
            Setting.simpleString(
                    "plugins.content_manager.catalog.content.consumer",
                    DEFAULT_CONTENT_CONSUMER,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    private final String ctiBaseUrl;
    private final int maximumItemsPerBulk;
    private final int maximumConcurrentBulks;
    private final long clientTimeout;
    private final int catalogSyncInterval;
    private final boolean updateOnStart;
    private final boolean updateOnSchedule;
    private final String contentContext;
    private final String contentConsumer;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings) {
        this.ctiBaseUrl = CTI_API_URL.get(settings);
        this.maximumItemsPerBulk = MAX_ITEMS_PER_BULK.get(settings);
        this.maximumConcurrentBulks = MAX_CONCURRENT_BULKS.get(settings);
        this.clientTimeout = CLIENT_TIMEOUT.get(settings);
        this.catalogSyncInterval = CATALOG_SYNC_INTERVAL.get(settings);
        this.updateOnStart = UPDATE_ON_START.get(settings);
        this.updateOnSchedule = UPDATE_ON_SCHEDULE.get(settings);
        this.contentContext = CONTENT_CONTEXT.get(settings);
        this.contentConsumer = CONTENT_CONSUMER.get(settings);
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
     * Retrieves the Content Context.
     *
     * @return the context string.
     */
    public String getContentContext() {
        return this.contentContext;
    }

    /**
     * Retrieves the Content Consumer.
     *
     * @return the consumer string.
     */
    public String getContentConsumer() {
        return this.contentConsumer;
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
                + "contentContext="
                + this.contentContext
                + ", "
                + "contentConsumer="
                + this.contentConsumer
                + "}";
    }
}
