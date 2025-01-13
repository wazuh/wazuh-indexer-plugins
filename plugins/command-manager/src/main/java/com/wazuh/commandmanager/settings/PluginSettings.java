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
package com.wazuh.commandmanager.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

import reactor.util.annotation.NonNull;

public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);
    private static final String BASE_PLUGINS_URI = "/_plugins";

    // Settings default values
    private static final Integer DEFAULT_TIMEOUT = 20;
    private static final Integer DEFAULT_SCHEDULE = 1;
    private static final Integer DEFAULT_PAGE_SIZE = 100;
    private static final Integer DEFAULT_KEEP_ALIVE = 30;
    /* DEFAULT_JOB_INDEX is retained and consumed as constant and not a Setting
     * because the job's index name value is used in the getJobIndex() getter function of
     * the CommandManagerPlugin class, it being required for the JobSchedulerExtension
     * interface, which is loaded before the settings.
     */
    private static final String DEFAULT_JOB_INDEX = ".scheduled-commands";
    private static final String DEFAULT_JOB_INDEX_TEMPLATE = "index-template-scheduled-commands";
    private static final String DEFAULT_PREFIX = "/_command_manager";
    private static final String DEFAULT_ENDPOINT = "/commands";
    private static final String DEFAULT_INDEX_NAME = ".commands";
    private static final String DEFAULT_INDEX_TEMPLATE = "index-template-commands";

    // Command Manager Settings.
    public static final Setting<Integer> TIMEOUT =
            Setting.intSetting(
                    "command_manager.timeout",
                    DEFAULT_TIMEOUT,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);
    public static final Setting<Integer> JOB_SCHEDULE =
            Setting.intSetting(
                    "command_manager.job.schedule",
                    DEFAULT_SCHEDULE,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);
    public static final Setting<Integer> JOB_PAGE_SIZE =
            Setting.intSetting(
                    "command_manager.job.page_size",
                    DEFAULT_PAGE_SIZE,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);
    public static final Setting<Integer> JOB_KEEP_ALIVE =
            Setting.intSetting(
                    "command_manager.job.pit_keep_alive",
                    DEFAULT_KEEP_ALIVE,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);
    public static final Setting<String> JOB_INDEX_TEMPLATE =
            Setting.simpleString(
                    "command_manager.job.index.template",
                    DEFAULT_JOB_INDEX_TEMPLATE,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);
    public static final Setting<String> API_PREFIX =
            Setting.simpleString(
                    "command_manager.api.prefix",
                    DEFAULT_PREFIX,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);
    public static final Setting<String> API_ENDPOINT =
            Setting.simpleString(
                    "command_manager.api.endpoint",
                    DEFAULT_ENDPOINT,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);
    public static final Setting<String> INDEX_NAME =
            Setting.simpleString(
                    "command_manager.index.name",
                    DEFAULT_INDEX_NAME,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);
    public static final Setting<String> INDEX_TEMPLATE =
            Setting.simpleString(
                    "command_manager.index.template",
                    DEFAULT_INDEX_TEMPLATE,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    private final Integer timeout;
    private final Integer jobSchedule;
    private final Integer jobPageSize;
    private final Integer jobKeepAlive;
    private final String jobIndexTemplate;
    private final String apiPrefix;
    private final String apiEndpoint;
    private final String indexName;
    private final String indexTemplate;
    private final String apiCommandsUri;
    private final String apiBaseUri;

    private static volatile PluginSettings instance;

    /** Private default constructor */
    private PluginSettings(@NonNull final Settings settings) {
        this.timeout = TIMEOUT.get(settings);
        this.jobSchedule = JOB_SCHEDULE.get(settings);
        this.jobPageSize = JOB_PAGE_SIZE.get(settings);
        this.jobKeepAlive = JOB_KEEP_ALIVE.get(settings);
        this.jobIndexTemplate = JOB_INDEX_TEMPLATE.get(settings);
        this.apiPrefix = API_PREFIX.get(settings);
        this.apiEndpoint = API_ENDPOINT.get(settings);
        this.indexName = INDEX_NAME.get(settings);
        this.indexTemplate = INDEX_TEMPLATE.get(settings);

        this.apiBaseUri = BASE_PLUGINS_URI + apiPrefix;
        this.apiCommandsUri = apiBaseUri + apiEndpoint;

        log.info("[SETTINGS] Timeout: {}", this.timeout);
        log.info("[SETTINGS] Job Schedule: {}", this.jobSchedule);
        log.info("[SETTINGS] Job Page Size: {}", this.jobPageSize);
        log.info("[SETTINGS] Job Keep Alive: {}", this.jobKeepAlive);
        log.info("[SETTINGS] Job Index Template: {}", this.jobIndexTemplate);
        log.info("[SETTINGS] API Prefix: {}", this.apiPrefix);
        log.info("[SETTINGS] API Endpoint: {}", this.apiEndpoint);
        log.info("[SETTINGS] API Base URI: {}", this.apiBaseUri);
        log.info("[SETTINGS] API Commands URI: {}", this.apiCommandsUri);
        log.info("[SETTINGS] Index Name: {}", this.indexName);
        log.info("[SETTINGS] Index Template: {}", this.indexTemplate);
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @return {@link PluginSettings#instance}
     */
    public static PluginSettings getInstance(@NonNull final Settings settings) {
        if (instance == null) {
            synchronized (PluginSettings.class) {
                if (instance == null) {
                    instance = new PluginSettings(settings);
                }
            }
        }
        return instance;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#instance}
     */
    public static PluginSettings getInstance() {
        if (instance == null) {
            throw new IllegalStateException("Plugin settings have not been initialized.");
        }
        return instance;
    }

    public Integer getTimeout() {
        return timeout;
    }

    public Integer getJobSchedule() {
        return jobSchedule;
    }

    public Integer getJobPageSize() {
        return jobPageSize;
    }

    public Integer getJobKeepAlive() {
        return jobKeepAlive;
    }

    public static String getJobIndexName() {
        return DEFAULT_JOB_INDEX;
    }

    public String getJobIndexTemplate() {
        return jobIndexTemplate;
    }

    public String getApiPrefix() {
        return apiPrefix;
    }

    public String getApiEndpoint() {
        return apiEndpoint;
    }

    public String getApiBaseUri() {
        return apiBaseUri;
    }

    public String getApiCommandsUri() {
        return apiCommandsUri;
    }

    public String getIndexName() {
        return indexName;
    }

    public String getIndexTemplate() {
        return indexTemplate;
    }

    @Override
    public String toString() {
        return "PluginSettings{"
                + "timeout="
                + timeout
                + ", jobSchedule='"
                + jobSchedule
                + '\''
                + ", jobPageSize="
                + jobPageSize
                + ", jobKeepAlive="
                + jobKeepAlive
                + '\''
                + ", jobIndexTemplate='"
                + jobIndexTemplate
                + '\''
                + ", apiBaseUri='"
                + apiBaseUri
                + '\''
                + ", apiCommandsUri='"
                + apiCommandsUri
                + '\''
                + ", indexName='"
                + indexName
                + '\''
                + ", indexTemplate='"
                + indexTemplate
                + '\''
                + '}';
    }
}
