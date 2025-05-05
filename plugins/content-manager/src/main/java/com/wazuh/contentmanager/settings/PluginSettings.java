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
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

import com.wazuh.contentmanager.utils.ClusterInfoHelper;
import reactor.util.annotation.NonNull;

/**
 * This class encapsulates configuration settings and constants for the Content Manager plugin. It
 * uses a singleton pattern to ensure a single instance is initialized and used throughout the
 * application. The settings are typically pulled from a configuration file and provide important
 * parameters such as API endpoints, timeouts, and execution settings.
 *
 * <p>Key responsibilities of this class include: - Managing plugin-wide settings for API URLs,
 * maximum attempts, timeouts, document limits, and more. - Providing initialized configuration
 * settings to other components. - Ensuring the settings are properly loaded and accessible via a
 * singleton instance.
 */
public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    // Settings default values
    private static final Integer DEFAULT_CTI_MAX_ATTEMPTS = 3;
    private static final Integer DEFAULT_CTI_SLEEP_TIME = 60;
    private static final Integer DEFAULT_HTTP_CLIENT_TIMEOUT = 10;

    private static final Integer DEFAULT_MAX_DOCS = 1000;
    private static final Integer DEFAULT_JOB_SCHEDULE = 1;

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /** Content Manager Plugin API path. */
    public static final String API_BASE_URI = "/_plugins/_content_manager";

    /** Base Wazuh CTI URL */
    public static final String CTI_URL = "https://cti.wazuh.com";

    /** Content Manager CTI API setting field key */
    private static final String CONTENT_MANAGER_API_CTI = "content-manager.api.cti";

    /** Content Manager CTI API consumer id/name */
    public static final String CONSUMER_ID = "vd_4.8.0";

    /** Content Manager CTI API context id/name */
    public static final String CONTEXT_ID = "vd_1.0.0";

    /** Read the CTI API URL from configuration file */
    public static final Setting<String> CTI_API_URL =
            Setting.simpleString(
                    CONTENT_MANAGER_API_CTI,
                    CTI_URL + "/api/v1",
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The maximum number of retries for a request to the CTI Client */
    public static final Setting<Integer> CTI_CLIENT_MAX_ATTEMPTS =
            Setting.intSetting(
                    "content_manager.cti.client.max_attempts",
                    DEFAULT_CTI_MAX_ATTEMPTS,
                    2,
                    5,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The sleep duration for the CTI client in seconds. */
    public static final Setting<Integer> CTI_CLIENT_SLEEP_TIME =
            Setting.intSetting(
                    "content_manager.cti.client.sleep_time",
                    DEFAULT_CTI_SLEEP_TIME,
                    20,
                    100,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The timeout duration for the HTTP client in seconds. */
    public static final Setting<Integer> HTTP_CLIENT_TIMEOUT =
            Setting.intSetting(
                    "content_manager.http.client.timeout",
                    DEFAULT_HTTP_CLIENT_TIMEOUT,
                    30,
                    50,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The maximum number of documents to return from a content */
    public static final Setting<Integer> CONTENT_INDEX_MAX_DOCUMENTS =
            Setting.intSetting(
                    "content_manager.content_index.max_documents",
                    25,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The maximum number of concurrent petitions allowed to the content index. */
    public static final Setting<Integer> CONTENT_INDEX_MAX_CONCURRENT_PETITIONS =
            Setting.intSetting(
                    "content_manager.content_index.max_concurrent_petitions",
                    5,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The timeout duration for 'get' operations on the content index in seconds. */
    public static final Setting<Long> CONTENT_INDEX_TIMEOUT =
            Setting.longSetting(
                    "content_manager.content_index.timeout",
                    10,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The timeout duration for 'get' operations on the context index in seconds. */
    public static final Setting<Long> CONTEXT_INDEX_TIMEOUT =
            Setting.longSetting(
                    "content_manager.context_index.timeout",
                    10,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The maximum size of a chunk for the content updater. */
    public static final Setting<Long> CHUNK_MAX_SIZE =
            Setting.longSetting(
                    "content_manager.chunk.max_size",
                    1000,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Content Manager Settings. Maximum number of documents to be returned by query. */
    public static final Setting<Integer> JOB_MAX_DOCS =
            Setting.intSetting(
                    "content_manager.job.max_docs",
                    DEFAULT_MAX_DOCS,
                    5,
                    100000,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Job execution interval in minutes. */
    public static final Setting<Integer> JOB_SCHEDULE =
            Setting.intSetting(
                    "content_manager.job.schedule",
                    DEFAULT_JOB_SCHEDULE,
                    1,
                    10,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    private final String ctiBaseUrl;
    private final ClusterService clusterService;
    private final Integer ctiClientMaxAttempts;
    private final Integer ctiClientSleepTime;
    private final Integer httpClientTimeout;
    private final Integer contentIndexMaximumDocuments;
    private final Integer contentIndexMaximumConcurrentPetitions;
    private final Long contentIndexTimeout;
    private final Long contextIndexTimeout;
    private final Long chunkMaxSize;
    private final Integer jobMaximumDocuments;
    private final Integer jobSchedule;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings, ClusterService clusterService) {
        this.ctiBaseUrl = CTI_API_URL.get(settings);
        this.clusterService = clusterService;
        this.ctiClientMaxAttempts = CTI_CLIENT_MAX_ATTEMPTS.get(settings);
        this.ctiClientSleepTime = CTI_CLIENT_SLEEP_TIME.get(settings);
        this.httpClientTimeout = HTTP_CLIENT_TIMEOUT.get(settings);
        this.contentIndexMaximumDocuments = CONTENT_INDEX_MAX_DOCUMENTS.get(settings);
        this.contentIndexMaximumConcurrentPetitions =
                CONTENT_INDEX_MAX_CONCURRENT_PETITIONS.get(settings);
        this.contentIndexTimeout = CONTENT_INDEX_TIMEOUT.get(settings);
        this.contextIndexTimeout = CONTEXT_INDEX_TIMEOUT.get(settings);
        this.chunkMaxSize = CHUNK_MAX_SIZE.get(settings);
        this.jobMaximumDocuments = JOB_MAX_DOCS.get(settings);
        this.jobSchedule = JOB_SCHEDULE.get(settings);

        log.debug("Settings.loaded: {}", this.toString());
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @param settings as obtained in createComponents.
     * @param clusterService service to get cluster stats.
     * @return {@link PluginSettings#INSTANCE}
     */
    public static synchronized PluginSettings getInstance(
            @NonNull final Settings settings, ClusterService clusterService) {
        if (INSTANCE == null) {
            INSTANCE = new PluginSettings(settings, clusterService);
        }
        return INSTANCE;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#INSTANCE}
     * @throws IllegalStateException if the instance has not been initialized
     * @see PluginSettings#getInstance(Settings, ClusterService)
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
     * Getter method for the Command Manager API URL
     *
     * @return a string with the Content Manager full URL
     */
    public String getClusterBaseUrl() {
        return ClusterInfoHelper.getClusterBaseUrl(this.clusterService);
    }

    public Integer getCtiClientMaxAttempts() {
        return ctiClientMaxAttempts;
    }

    /**
     * Retrieves the sleep time used by the CTI client.
     *
     * @return an Integer representing the duration of the sleep time for the CTI client.
     */
    public Integer getCtiClientSleepTime() {
        return ctiClientSleepTime;
    }

    /**
     * Retrieves the timeout value for the HTTP client.
     *
     * @return an Integer representing the HTTP client timeout in milliseconds.
     */
    public Integer getHttpClientTimeout() {
        return httpClientTimeout;
    }

    /**
     * Retrieves the maximum number of documents that can be indexed.
     *
     * @return an Integer representing the maximum number of documents allowed for content indexing.
     */
    public Integer getContentIndexMaximumDocuments() {
        return contentIndexMaximumDocuments;
    }

    /**
     * Retrieves the maximum number of concurrent petitions allowed for content indexing.
     *
     * @return an Integer representing the maximum number of concurrent petitions.
     */
    public Integer getContentIndexMaximumConcurrentPetitions() {
        return contentIndexMaximumConcurrentPetitions;
    }

    /**
     * Retrieves the timeout value for content indexing operations.
     *
     * @return a Long representing the timeout duration for content indexing, in milliseconds.
     */
    public Long getContentIndexTimeout() {
        return contentIndexTimeout;
    }

    /**
     * Retrieves the timeout value for context indexing operations.
     *
     * @return a Long representing the timeout duration for context indexing, in milliseconds.
     */
    public Long getContextIndexTimeout() {
        return contextIndexTimeout;
    }

    /**
     * Retrieves the maximum size of a chunk.
     *
     * @return a Long representing the maximum size of a chunk.
     */
    public Long getChunkMaxSize() {
        return chunkMaxSize;
    }

    /**
     * Retrieves the maximum number of documents allowed for a job.
     *
     * @return an Integer representing the maximum number of documents that can be processed in a
     *     single job.
     */
    public Integer getJobMaximumDocuments() {
        return jobMaximumDocuments;
    }

    /**
     * Retrieves the job schedule interval.
     *
     * @return an Integer representing the job execution interval in minutes
     */
    public Integer getJobSchedule() {
        return jobSchedule;
    }
}
