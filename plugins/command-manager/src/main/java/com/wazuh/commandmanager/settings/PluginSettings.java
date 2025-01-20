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
    private static final Integer DEFAULT_PAGE_SIZE = 100;
    private static final Integer DEFAULT_CLIENT_TIMEOUT = 30;
    private static final Integer DEFAULT_JOB_SCHEDULE = 1;
    private static final Integer DEFAULT_PIT_KEEP_ALIVE = 60;
    /* Some configurations were kept as constants rather than settings preventing
    runtime changes, which could lead to inconsistencies within plugin components
    and external interactions.
    */
    private static final String JOB_TYPE = "command_manager_scheduler_extension";
    private static final String JOB_INDEX_TEMPLATE = "index-template-scheduled-commands";
    private static final String JOB_INDEX = ".scheduled-commands";
    private static final String COMMAND_INDEX_TEMPLATE = "index-template-commands";
    private static final String COMMAND_INDEX = ".commands";
    private static final String API_BASE_URI = "/_plugins/_command_manager";
    private static final String API_COMMANDS_ENDPOINT = API_BASE_URI + "/commands";

    // Command Manager Settings.
    // Number of commands to be returned per search results page
    public static final Setting<Integer> JOB_PAGE_SIZE =
            Setting.intSetting(
                    "command_manager.job.page_size",
                    DEFAULT_PAGE_SIZE,
                    5,
                    100000,
                    Setting.Property.Consistent,
                    Setting.Property.Filtered);
    // Client class methods' timeout in seconds
    // Currently used for client.index() and client.search() methods.
    public static final Setting<Integer> CLIENT_TIMEOUT =
            Setting.intSetting(
                    "command_manager.client.timeout",
                    DEFAULT_CLIENT_TIMEOUT,
                    5,
                    120,
                    Setting.Property.Consistent,
                    Setting.Property.Filtered);
    // Job execution interval in minutes.
    // Must be greater than CLIENT_TIMEOUT
    public static final Setting<Integer> JOB_SCHEDULE =
            Setting.intSetting(
                    "command_manager.job.schedule",
                    DEFAULT_JOB_SCHEDULE,
                    1,
                    10,
                    Setting.Property.Consistent,
                    Setting.Property.Filtered);
    // Time to live of the Point In Time index snapshot in seconds.
    // Must be equal or greater than JOB_SCHEDULE
    public static final Setting<Integer> PIT_KEEP_ALIVE =
            Setting.intSetting(
                    "command_manager.job.pit_keep_alive",
                    DEFAULT_PIT_KEEP_ALIVE,
                    60,
                    600,
                    Setting.Property.Consistent,
                    Setting.Property.Filtered);

    private Integer timeout;
    private final Integer jobSchedule;
    private final Integer jobPageSize;
    private Integer pitKeepAlive;

    private static volatile PluginSettings instance;

    /** Private default constructor */
    private PluginSettings(@NonNull final Settings settings) {
        this.timeout = CLIENT_TIMEOUT.get(settings);
        this.jobSchedule = JOB_SCHEDULE.get(settings);
        this.jobPageSize = JOB_PAGE_SIZE.get(settings);
        this.pitKeepAlive = PIT_KEEP_ALIVE.get(settings);
        validateSettings();
    }

    /**
     * Fits setting values to the internal logic
     */
    private void validateSettings() {
        // If timeout is not less than job period in seconds
        if ( !(this.timeout < this.jobSchedule * 60) ) {
            // Set timeout to half job period (in seconds)
            this.timeout = this.jobSchedule * 30;
        }
        // If the pit keep alive is less than the job's period in seconds
        if ( this.pitKeepAlive < this.jobSchedule * 60 ) {
            // Make the keep alive equal to jobSchedule
            // This is to make the Pit available throughout the duration of the job
            this.pitKeepAlive = this.jobSchedule * 60;
        }
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
        return this.timeout;
    }

    /**
     * @return the job schedule value
     */
    public Integer getJobSchedule() {
        return this.jobSchedule;
    }

    /**
     * @return the job page size value
     */
    public Integer getJobPageSize() {
        return this.jobPageSize;
    }

    /**
     * @return the job keep-alive value
     */
    public Integer getPitKeepAlive() {
        return this.pitKeepAlive;
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
    public static String getJobIndexTemplate() {
        return JOB_INDEX_TEMPLATE;
    }

    /**
     * @return the API prefix
     */
    public static String getApiPrefix() {
        return API_BASE_URI;
    }

    /**
     * @return the URI for the commands API endpoint
     */
    public static String getApiCommandsEndpoint() {
        return API_COMMANDS_ENDPOINT;
    }

    /**
     * @return the index name
     */
    public static String getIndexName() {
        return COMMAND_INDEX;
    }

    /**
     * @return the index template
     */
    public static String getIndexTemplate() {
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
                + pitKeepAlive
                + '\''
                + ", jobIndexTemplate='"
                + JOB_INDEX_TEMPLATE
                + '\''
                + ", apiBaseUri='"
                + API_BASE_URI
                + '\''
                + ", apiCommandsUri='"
                + API_COMMANDS_ENDPOINT
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
