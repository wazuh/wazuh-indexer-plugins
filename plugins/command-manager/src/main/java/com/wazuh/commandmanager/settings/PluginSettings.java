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
    private static final String M_API_PREFIX = "management_api";
    private static final String C_M_PREFIX = "command_manager";

    // Management API settings
    public static final Setting<String> M_API_URI = Setting.simpleString(
            M_API_PREFIX + ".host", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> M_API_RETRIES = Setting.intSetting(
            M_API_PREFIX + ".retries", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> M_API_TIMEOUT = Setting.intSetting(
            M_API_PREFIX + ".timeout", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Management API Auth settings
    public static final Setting<String> M_API_AUTH_USERNAME = Setting.simpleString(
            M_API_PREFIX + ".auth.username", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> M_API_AUTH_PASSWORD = Setting.simpleString(
            M_API_PREFIX + ".auth.password", Setting.Property.NodeScope, Setting.Property.Filtered);

    // Command Manager settings
    public static final Setting<Integer> C_M_TIMEOUT = Setting.intSetting(
            C_M_PREFIX + ".timeout", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Command Manager Job settings
    public static final Setting<String> C_M_JOB_SCHEDULE = Setting.simpleString(
            C_M_PREFIX + ".job.schedule", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> C_M_JOB_PAGE_SIZE = Setting.intSetting(
            C_M_PREFIX + ".job.page_size", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> C_M_JOB_KEEP_ALIVE = Setting.intSetting(
            C_M_PREFIX + ".job.pit_keep_alive", Integer.MIN_VALUE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> C_M_JOB_INDEX_NAME = Setting.simpleString(
            C_M_PREFIX + ".job.index.name", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> C_M_JOB_INDEX_TEMPLATE = Setting.simpleString(
            C_M_PREFIX + ".job.index.template", Setting.Property.NodeScope, Setting.Property.Filtered);

    // Command Manager API settings
    public static final Setting<String> C_M_API_PREFIX = Setting.simpleString(
            C_M_PREFIX + ".api.prefix", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> C_M_API_ENDPOINT = Setting.simpleString(
            C_M_PREFIX + ".api.endpoint", Setting.Property.NodeScope, Setting.Property.Filtered);

    // Command Manager Index settings
    public static final Setting<String> C_M_INDEX_NAME = Setting.simpleString(
            C_M_PREFIX + ".index.name", Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> C_M_INDEX_TEMPLATE = Setting.simpleString(
            C_M_PREFIX + ".index.template", Setting.Property.NodeScope, Setting.Property.Filtered);

    private static PluginSettings instance;

    private final String authUsername;
    private final String authPassword;
    private final String uri;
    public final int retries;
    public final int apiTimeout;
    public final int timeout;
    public final String jobSchedule;
    public final int jobPageSize;
    public final int jobKeepAlive;
    public final String jobIndexName;
    public final String jobIndexTemplate;
    public final String apiPrefix;
    public final String apiEndpoint;
    public final String indexName;
    public final String indexTemplate;

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
        this.indexName = C_M_INDEX_NAME.get(settings);
        this.indexTemplate = C_M_INDEX_TEMPLATE.get(settings);

        log.info("[SETTINGS] Username: {}", this.authUsername);
        log.info("[SETTINGS] URI: {}", this.uri);
        log.info("[SETTINGS] Retries: {}", this.retries);
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
