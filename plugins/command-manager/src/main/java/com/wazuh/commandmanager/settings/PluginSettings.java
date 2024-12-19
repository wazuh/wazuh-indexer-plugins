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

import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;

import java.net.URISyntaxException;

import reactor.util.annotation.NonNull;


public class PluginSettings {
    public static final String BASE_PLUGINS_URI = "/_plugins";

    // Management API settings
    public static final Setting<String> M_API_URI = Setting.simpleString(
            "management_api.host", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> M_API_RETRIES = Setting.intSetting(
            "management_api.retries", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> M_API_TIMEOUT = Setting.intSetting(
            "management_api.timeout", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Management API Auth settings
    public static final Setting<String> M_API_AUTH_USERNAME = Setting.simpleString(
            "management_api.auth.username", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> M_API_AUTH_PASSWORD = Setting.simpleString(
            "management_api.auth.password", Setting.Property.NodeScope, Setting.Property.Filtered);

    // Command Manager settings
    public static final Setting<Integer> C_M_TIMEOUT = Setting.intSetting(
            "command_manager.timeout", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Command Manager Job settings
    public static final Setting<String> C_M_JOB_SCHEDULE = Setting.simpleString(
            "command_manager.job.schedule", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> C_M_JOB_PAGE_SIZE = Setting.intSetting(
            "command_manager.job.page_size", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> C_M_JOB_KEEP_ALIVE = Setting.intSetting(
            "command_manager.job.pit_keep_alive", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> C_M_JOB_INDEX_NAME = Setting.simpleString(
            "command_manager.job.index.name", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> C_M_JOB_INDEX_TEMPLATE = Setting.simpleString(
            "command_manager.job.index.template", Setting.Property.NodeScope, Setting.Property.Filtered);

    // Command Manager API settings
    public static final Setting<String> C_M_API_PREFIX = Setting.simpleString(
            "command_manager.api.prefix", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> C_M_API_ENDPOINT = Setting.simpleString(
            "command_manager.api.endpoint", Setting.Property.NodeScope, Setting.Property.Filtered);

    // Command Manager Index settings
    public static final Setting<String> C_M_INDEX_NAME = Setting.simpleString(
            "command_manager.index.name", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> C_M_INDEX_TEMPLATE = Setting.simpleString(
            "command_manager.index.template", Setting.Property.NodeScope, Setting.Property.Filtered);

    private static PluginSettings instance;

    private final String authUsername;
    private final String authPassword;
    private final String uri;
    private final int retries;
    private final int apiTimeout;
    private final int timeout;
    private final String jobSchedule;
    private final int jobPageSize;
    private final int jobKeepAlive;
    private final String jobIndexName;
    private final String jobIndexTemplate;
    private final String apiPrefix;
    private final String apiEndpoint;
    private final String apiBaseUri;
    private final String apiCommandsUri;
    private final String indexName;
    private final String indexTemplate;

    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    /** Private default constructor */
    private PluginSettings(@NonNull final Settings settings) {
        log.info("Plugin created with the keystore information.");

        this.authUsername = M_API_AUTH_USERNAME.get(settings);
        this.authPassword = M_API_AUTH_PASSWORD.get(settings);
        this.uri = M_API_URI.get(settings);
        this.retries = M_API_RETRIES.get(settings);
        this.apiTimeout = M_API_TIMEOUT.get(settings);
        this.timeout = M_API_TIMEOUT.get(settings);
        this.jobSchedule = C_M_JOB_SCHEDULE.get(settings);
        this.jobPageSize = C_M_JOB_PAGE_SIZE.get(settings);
        this.jobKeepAlive = C_M_JOB_KEEP_ALIVE.get(settings);
        this.jobIndexName = C_M_JOB_INDEX_NAME.get(settings);
        this.jobIndexTemplate = C_M_JOB_INDEX_TEMPLATE.get(settings);
        this.apiPrefix = C_M_API_PREFIX.get(settings);
        this.apiEndpoint = C_M_API_ENDPOINT.get(settings);
        this.apiBaseUri = BASE_PLUGINS_URI + apiPrefix;
        this.apiCommandsUri = apiBaseUri + apiEndpoint;
        this.indexName = C_M_INDEX_NAME.get(settings);
        this.indexTemplate = C_M_INDEX_TEMPLATE.get(settings);

        log.info("[SETTINGS] Username: {}", this.authUsername);
        log.info("[SETTINGS] URI: {}", this.uri);
        log.info("[SETTINGS] Retries: {}", this.retries);
        log.info("[SETTINGS] API Timeout: {}", this.apiTimeout);
        log.info("[SETTINGS] Timeout: {}", this.timeout);
        log.info("[SETTINGS] jobSchedule: {}", jobSchedule);
        log.info("[SETTINGS] jobPageSize: {}", jobPageSize);
        log.info("[SETTINGS] jobKeepAlive: {}", jobKeepAlive);
        log.info("[SETTINGS] jobIndexName: {}", jobIndexName);
        log.info("[SETTINGS] jobIndexTemplate: {}", jobIndexTemplate);
        log.info("[SETTINGS] apiPrefix: {}", apiPrefix);
        log.info("[SETTINGS] apiEndpoint: {}", apiEndpoint);
        log.info("[SETTINGS] indexName: {}", indexName);
        log.info("[SETTINGS] indexTemplate: {}", indexTemplate);
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @return {@link PluginSettings#instance}
     */
    public static PluginSettings getInstance(@NonNull final Settings settings) {
        if (PluginSettings.instance == null) {
            instance = new PluginSettings(settings);
        }
        return instance;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#instance}
     */
    public static PluginSettings getInstance() {
        if (PluginSettings.instance == null) {
            throw new IllegalStateException("Plugin settings have not been initialized.");
        }
        return instance;
    }

    public String getAuthPassword() {
        return this.authPassword;
    }

    public String getAuthUsername() {
        return this.authUsername;
    }

    public String getUri() {
        return this.uri;
    }

    public String getUri(String path) throws URISyntaxException {
        return new URIBuilder(getUri()).setPath(path).build().toString();
    }

    public int getRetries() {
        return retries;
    }

    public int getApiTimeout() {
        return apiTimeout;
    }

    public int getTimeout() {
        return timeout;
    }

    public String getJobSchedule() {
        return jobSchedule;
    }

    public int getJobPageSize() {
        return jobPageSize;
    }

    public int getJobKeepAlive() {
        return jobKeepAlive;
    }

    public String getJobIndexName() {
        return jobIndexName;
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
                + "authUsername='"
                + getAuthUsername()
                + '\''
                + ", authPassword='"
                + getAuthUsername()
                + '\''
                + ", uri='"
                + getUri()
                + '\''
                + '}';
    }
}
