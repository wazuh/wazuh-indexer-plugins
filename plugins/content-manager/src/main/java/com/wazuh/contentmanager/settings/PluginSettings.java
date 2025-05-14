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
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;

import com.wazuh.contentmanager.utils.ClusterInfo;
import reactor.util.annotation.NonNull;

/** This class encapsulates configuration settings and constants for the Content Manager plugin. */
public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    /** Settings default values */
    private static final String DEFAULT_CONSUMER_ID = "vd_4.8.0";

    private static final String DEFAULT_CONTEXT_ID = "vd_1.0.0";
    private static final int DEFAULT_CTI_MAX_ATTEMPTS = 3;
    private static final int DEFAULT_CTI_SLEEP_TIME = 60;
    private static final int DEFAULT_MAX_ITEMS_PER_BULK = 25;
    private static final int DEFAULT_MAX_CONCURRENT_BULKS = 5;
    private static final int DEFAULT_CLIENT_TIMEOUT = 10;
    private static final int DEFAULT_MAX_CHANGES = 1000;
    private static final int DEFAULT_MAX_DOCS = 1000;
    private static final int DEFAULT_JOB_SCHEDULE = 1;

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /** Base Wazuh CTI URL */
    public static final String CTI_URL = "https://cti.wazuh.com";

    /** The CTI API URL from the configuration file */
    public static final Setting<String> CTI_API_URL =
            Setting.simpleString(
                    "content_manager.cti.api",
                    CTI_URL + "/api/v1",
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Content Manager CTI API consumer id/name */
    public static final Setting<String> CONSUMER_ID =
            Setting.simpleString(
                    "content_manager.cti.consumer",
                    DEFAULT_CONSUMER_ID,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Content Manager CTI API context id/name */
    public static final Setting<String> CONTEXT_ID =
            Setting.simpleString(
                    "content_manager.cti.context",
                    DEFAULT_CONTEXT_ID,
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
     * Specifies the initial wait time in seconds for the first retry to the CTI API after receiving a
     * 'Too Many Requests' response or other retry conditions. This value also serves as the base for
     * calculating increased wait times for subsequent retries, helping to manage request rates and
     * prevent server overload.
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
                    "content_manager.max_concurrent_bulks",
                    DEFAULT_MAX_CONCURRENT_BULKS,
                    1,
                    5,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Timeout of indexing operations */
    public static final Setting<Long> CLIENT_TIMEOUT =
            Setting.longSetting(
                    "content_manager.client.timeout",
                    DEFAULT_CLIENT_TIMEOUT,
                    10,
                    50,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** The maximum number of changes to be fetched and applied during the update of the content. */
    public static final Setting<Long> MAX_CHANGES =
            Setting.longSetting(
                    "content_manager.max_changes",
                    DEFAULT_MAX_CHANGES,
                    10,
                    1000,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Command Manager authentication user. */
    public static final Setting<SecureString> INDEXER_USERNAME =
            SecureSetting.secureString("indexer.username", null);

    /** Command Manager authentication password. */
    public static final Setting<SecureString> INDEXER_PASSWORD =
            SecureSetting.secureString("indexer.password", null);

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

    private final SecureString username;
    private final SecureString password;

    private final int ctiClientMaxAttempts;
    private final int ctiClientSleepTime;
    private final int maximumItemsPerBulk;
    private final int maximumConcurrentBulks;
    private final long clientTimeout;
    private final long maximumChanges;
    private final int jobMaximumDocuments;
    private final int jobSchedule;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings, ClusterService clusterService) {
        this.ctiBaseUrl = CTI_API_URL.get(settings);
        this.username = INDEXER_USERNAME.get(settings);
        this.password = INDEXER_PASSWORD.get(settings);

        if (validateConsumerId(CONSUMER_ID.get(settings))) {
            this.consumerId = CONSUMER_ID.get(settings);
        } else {
            this.consumerId = DEFAULT_CONSUMER_ID;
            log.error(
                    "Setting [content_manager.cti.consumer] must follow the patter 'vd_{Number}.{Number}.{Number}'. Falling back to the default value [{}]",
                    DEFAULT_CONSUMER_ID);
        }

        if (validateContextId(CONTEXT_ID.get(settings))) {
            this.contextId = CONTEXT_ID.get(settings);
        } else {
            this.contextId = DEFAULT_CONTEXT_ID;
            log.error(
                    "Setting [content_manager.cti.context] must follow the patter 'vd_{Number}.{Number}.{Number}'. Falling back to the default value [{}]",
                    DEFAULT_CONTEXT_ID);
        }

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
        return this.consumerId;
    }

    /**
     * Retrieves the context ID.
     *
     * @return a String representing the context ID.
     */
    public String getContextId() {
        return this.contextId;
    }

    /**
     * Getter method for the Command Manager API URL
     *
     * @return a string with the Content Manager full URL
     */
    public String getClusterBaseUrl() {
        return ClusterInfo.getClusterBaseUrl(this.clusterService);
    }

    /**
     * Indexer's username getter.
     *
     * @return a string with the Indexer's authentication username.
     */
    public String getUsername() {
        return this.username.toString();
    }

    /**
     * Indexer's password getter.
     *
     * @return a string with the Indexer's authentication password.
     */
    public String getPassword() {
        return this.password.toString();
    }

    /*
     * Retrieves the maximum number of retry attempts allowed for the CTI client.
     *
     * @return an Integer representing the maximum number of retry attempts.
     */
    public Integer getCtiClientMaxAttempts() {
        return this.ctiClientMaxAttempts;
    }

    /**
     * Retrieves the wait time used by the CTI client after receiving a 'too many requests' response.
     * This attribute helps calculate the delay before retrying the request.
     *
     * @return an Integer representing the duration of the sleep time for the CTI client.
     */
    public Integer getCtiClientSleepTime() {
        return this.ctiClientSleepTime;
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
     * Retrieves the maximum number of changes to be fetched and applied during the update of the
     * content.
     *
     * @return a Long representing the maximum number of changes.
     */
    public Long getMaximumChanges() {
        return this.maximumChanges;
    }

    /**
     * Retrieves the maximum number of documents allowed for a job.
     *
     * @return an Integer representing the maximum number of documents that can be processed in a
     *     single job.
     */
    public Integer getJobMaximumDocuments() {
        return this.jobMaximumDocuments;
    }

    /**
     * Retrieves the job schedule interval.
     *
     * @return an Integer representing the job execution interval in minutes
     */
    public Integer getJobSchedule() {
        return this.jobSchedule;
    }

    /**
     * Validates the given consumer ID against a predefined format. The consumer ID should match the
     * pattern {@code vd_<1-2 digits>.<1-2 digits>.<1-2 digits>}.
     *
     * @param consumerId the consumer ID to validate
     * @return true if the consumer ID matches the expected format, false otherwise
     */
    public static Boolean validateConsumerId(String consumerId) {
        String regex = "vd_\\d{1,2}\\.\\d{1,2}\\.\\d{1,2}";

        // Ensure the context id have the correct format
        return consumerId.matches(regex);
    }

    /**
     * Validates the given context ID against a predefined format. The context ID should match the
     * pattern {@code vd_<1-2 digits>.<1-2 digits>.<1-2 digits>}.
     *
     * @param contextId the context ID to validate
     * @return true if the context ID matches the expected format, false otherwise
     */
    public static Boolean validateContextId(String contextId) {
        String regex = "vd_\\d{1,2}\\.\\d{1,2}\\.\\d{1,2}";

        // Ensure the context id have the correct format
        return contextId.matches(regex);
    }

    @Override
    public String toString() {
        return "{"
                + "ctiBaseUrl='"
                + this.ctiBaseUrl
                + "', "
                + "consumerId='"
                + this.consumerId
                + "', "
                + "contextId='"
                + this.contextId
                + "', "
                + "ctiClientMaxAttempts="
                + this.ctiClientMaxAttempts
                + ", "
                + "ctiClientSleepTime="
                + this.ctiClientSleepTime
                + ", "
                + "maximumItemsPerBulk="
                + this.maximumItemsPerBulk
                + ", "
                + "maximumConcurrentBulks="
                + this.maximumConcurrentBulks
                + ", "
                + "clientTimeout="
                + this.clientTimeout
                + ", "
                + "maximumChanges="
                + this.maximumChanges
                + ", "
                + "jobMaximumDocuments="
                + this.jobMaximumDocuments
                + ", "
                + "jobSchedule="
                + this.jobSchedule
                + "}";
    }
}
