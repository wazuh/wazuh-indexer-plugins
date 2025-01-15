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

    // Settings default values
    private static final Integer DEFAULT_TIMEOUT = 20;
    private static final Integer DEFAULT_SCHEDULE = 1;
    private static final Integer DEFAULT_PAGE_SIZE = 100;
    private static final Integer DEFAULT_KEEP_ALIVE = 30;
    /* JOB_INDEX and JOB_TYPE are retained and consumed as constants and not Settings
     * because these job's values are used in the corresponding getter functions of
     * the CommandManagerPlugin class, it being required for the JobSchedulerExtension
     * interface, which is loaded before the settings.
     */
    private static final String JOB_TYPE = "command_manager_scheduler_extension";
    private static final String JOB_INDEX_TEMPLATE = "index-template-scheduled-commands";
    private static final String JOB_INDEX = ".scheduled-commands";
    private static final String COMMAND_INDEX_TEMPLATE = "index-template-commands";
    private static final String COMMAND_INDEX = ".commands";
    private static final String BASE_PLUGINS_URI = "/_plugins";
    private static final String API_PREFIX = "/_command_manager";
    private static final String API_ENDPOINT = "/commands";

    // Command Manager Settings.
    public static final Setting<Integer> CLIENT_TIMEOUT =
            Setting.intSetting(
                    "command_manager.client.timeout",
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

    private final Integer timeout;
    private final Integer jobSchedule;
    private final Integer jobPageSize;
    private final Integer jobKeepAlive;
    private final String apiCommandsUri;
    private final String apiBaseUri;

    private static volatile PluginSettings instance;

    /** Private default constructor */
    private PluginSettings(@NonNull final Settings settings) {
        this.timeout = CLIENT_TIMEOUT.get(settings);
        this.jobSchedule = JOB_SCHEDULE.get(settings);
        this.jobPageSize = JOB_PAGE_SIZE.get(settings);
        this.jobKeepAlive = JOB_KEEP_ALIVE.get(settings);
        this.apiBaseUri = BASE_PLUGINS_URI + API_PREFIX;
        this.apiCommandsUri = apiBaseUri + API_ENDPOINT;
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

    /**
     * @return the timeout value
     */
    public Integer getTimeout() {
        return timeout;
    }

    /**
     * @return the job schedule value
     */
    public Integer getJobSchedule() {
        return jobSchedule;
    }

    /**
     * @return the job page size value
     */
    public Integer getJobPageSize() {
        return jobPageSize;
    }

    /**
     * @return the job keep-alive value
     */
    public Integer getJobKeepAlive() {
        return jobKeepAlive;
    }

    /**
     * @return the job index name
     */
    public static String getJobIndexName() {
        return JOB_INDEX;
    }

    /**
     * @return the job type
     */
    public static String getJobType() {
        return JOB_TYPE;
    }

    /**
     * @return the job index template
     */
    public String getJobIndexTemplate() {
        return JOB_INDEX_TEMPLATE;
    }

    /**
     * @return the API prefix
     */
    public String getApiPrefix() {
        return API_PREFIX;
    }

    /**
     * @return the API endpoint
     */
    public String getApiEndpoint() {
        return API_ENDPOINT;
    }

    /**
     * @return the base URI for the API
     */
    public String getApiBaseUri() {
        return apiBaseUri;
    }

    /**
     * @return the URI for the API commands
     */
    public String getApiCommandsUri() {
        return apiCommandsUri;
    }

    /**
     * @return the index name
     */
    public String getIndexName() {
        return COMMAND_INDEX;
    }

    /**
     * @return the index template
     */
    public String getIndexTemplate() {
        return COMMAND_INDEX_TEMPLATE;
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
                + JOB_INDEX_TEMPLATE
                + '\''
                + ", apiBaseUri='"
                + apiBaseUri
                + '\''
                + ", apiCommandsUri='"
                + apiCommandsUri
                + '\''
                + ", indexName='"
                + COMMAND_INDEX
                + '\''
                + ", indexTemplate='"
                + COMMAND_INDEX_TEMPLATE
                + '\''
                + ", jobIndex='"
                + JOB_INDEX
                + '\''
                + ", jobType='"
                + JOB_TYPE
                + '}';
    }
}
