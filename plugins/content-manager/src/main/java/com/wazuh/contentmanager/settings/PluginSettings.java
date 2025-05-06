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

/** This class encapsulates configuration settings and constants for the Content Manager plugin. */
public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    /** Settings default values */
    private static final Integer DEFAULT_CTI_MAX_ATTEMPTS = 3;

    private static final Integer DEFAULT_CTI_SLEEP_TIME = 60;
    private static final Integer DEFAULT_MAX_DOCS = 1000;
    private static final Integer DEFAULT_JOB_SCHEDULE = 1;

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /** Base Wazuh CTI URL */
    public static final String CTI_URL = "https://cti.wazuh.com";

    /** The CTI API URL from the configuration file */
    public static final Setting<String> CTI_API_URL =
            Setting.simpleString(
                    "content_manager.api.cti",
                    CTI_URL + "/api/v1",
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Content Manager CTI API consumer id/name */
    public static final Setting<String> CONSUMER_ID =
            Setting.simpleString(
                    "content_manager.cti.consumer",
                    "vd_4.8.0",
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Content Manager CTI API context id/name */
    public static final Setting<String> CONTEXT_ID =
            Setting.simpleString(
                    "content_manager.cti.context",
                    "vd_1.0.0",
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

    /**
     * This attribute helps calculate the delay before retrying the request to the CTI client in
     * seconds.
     */
    public static final Setting<Integer> CTI_CLIENT_SLEEP_TIME =
            Setting.intSetting(
                    "content_manager.cti.client.sleep_time",
                    DEFAULT_CTI_SLEEP_TIME,
                    20,
                    100,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * The maximum number of elements that are included in a bulk request during the initialization
     * from a snapshot.
     */
    public static final Setting<Integer> MAX_ITEMS_PER_BULK =
            Setting.intSetting(
                    "content_manager.max_items_per_bulk",
                    25,
                    10,
                    25,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * The maximum number of co-existing bulk operations during the initialization from a snapshot.
     */
    public static final Setting<Integer> MAX_CONCURRENT_BULKS =
            Setting.intSetting(
                    "content_manager.max_concurrent_bulks",
                    5,
                    1,
                    5,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * The timeout duration for 'get' operations on the content index and context index, in seconds.
     */
    public static final Setting<Long> CLIENT_TIMEOUT =
            Setting.longSetting(
                    "content_manager.client.timeout",
                    10,
                    10,
                    50,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The maximum number of changes to be fetched and applied during the update of the content. */
    public static final Setting<Long> MAX_CHANGES =
            Setting.longSetting(
                    "content_manager.max_changes",
                    1000,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Maximum number of documents processed per indexing job. */
    public static final Setting<Integer> JOB_MAX_DOCS =
            Setting.intSetting(
                    "content_manager.job.max_docs",
                    DEFAULT_MAX_DOCS,
                    5,
                    100000,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Interval in minutes between each scheduled job execution. */
    public static final Setting<Integer> JOB_SCHEDULE =
            Setting.intSetting(
                    "content_manager.job.schedule",
                    DEFAULT_JOB_SCHEDULE,
                    1,
                    10,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    private final String ctiBaseUrl;
    private final String consumerId;
    private final String contextId;
    private final ClusterService clusterService;
    private final Integer ctiClientMaxAttempts;
    private final Integer ctiClientSleepTime;
    private final Integer maximumItemsPerBulk;
    private final Integer maximumConcurrentBulks;
    private final Long clientTimeout;
    private final Long maximumChanges;
    private final Integer jobMaximumDocuments;
    private final Integer jobSchedule;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings, ClusterService clusterService) {
        this.ctiBaseUrl = CTI_API_URL.get(settings);
        this.consumerId = CONSUMER_ID.get(settings);
        this.contextId = CONTEXT_ID.get(settings);
        this.clusterService = clusterService;
        this.ctiClientMaxAttempts = CTI_CLIENT_MAX_ATTEMPTS.get(settings);
        this.ctiClientSleepTime = CTI_CLIENT_SLEEP_TIME.get(settings);
        this.maximumItemsPerBulk = MAX_ITEMS_PER_BULK.get(settings);
        this.maximumConcurrentBulks = MAX_CONCURRENT_BULKS.get(settings);
        this.clientTimeout = CLIENT_TIMEOUT.get(settings);
        this.maximumChanges = MAX_CHANGES.get(settings);
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
     * Retrieves the consumer ID.
     *
     * @return a string representing the consumer ID.
     */
    public String getConsumerId() {
        return consumerId;
    }

    /**
     * Retrieves the context ID.
     *
     * @return a String representing the context ID.
     */
    public String getContextId() {
        return contextId;
    }

    /**
     * Getter method for the Command Manager API URL
     *
     * @return a string with the Content Manager full URL
     */
    public String getClusterBaseUrl() {
        return ClusterInfoHelper.getClusterBaseUrl(this.clusterService);
    }

    /**
     * Retrieves the maximum number of retry attempts allowed for the CTI client.
     *
     * @return an Integer representing the maximum number of retry attempts.
     */
    public Integer getCtiClientMaxAttempts() {
        return ctiClientMaxAttempts;
    }

    /**
     * Retrieves the wait time used by the CTI client after receiving a 'too many requests' response.
     * This attribute helps calculate the delay before retrying the request.
     *
     * @return an Integer representing the duration of the sleep time for the CTI client.
     */
    public Integer getCtiClientSleepTime() {
        return ctiClientSleepTime;
    }

    /**
     * Retrieves the maximum number of documents that can be indexed.
     *
     * @return an Integer representing the maximum number of documents allowed for content indexing.
     */
    public Integer getMaxItemsPerBulk() {
        return maximumItemsPerBulk;
    }

    /**
     * Retrieves the maximum number of concurrent petitions allowed for content indexing.
     *
     * @return an Integer representing the maximum number of concurrent petitions.
     */
    public Integer getMaximumConcurrentBulks() {
        return maximumConcurrentBulks;
    }

    /**
     * Retrieves the timeout value for content and context indexing operations.
     *
     * @return a Long representing the timeout duration in seconds.
     */
    public Long getClientTimeout() {
        return clientTimeout;
    }

    /**
     * Retrieves the maximum number of changes to be fetched and applied during the update of the
     * content.
     *
     * @return a Long representing the maximum number of changes.
     */
    public Long getMaximumChanges() {
        return maximumChanges;
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
