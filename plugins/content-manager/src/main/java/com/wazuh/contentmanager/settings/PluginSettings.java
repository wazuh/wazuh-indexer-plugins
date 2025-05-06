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

import com.wazuh.contentmanager.utils.ClusterInfo;
import reactor.util.annotation.NonNull;

/** Singleton class to manage the plugin's settings. */
public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

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

    /** Timeout of indexing operations */
    public static final long TIMEOUT = 10L;

    private final String ctiBaseUrl;
    private final ClusterService clusterService;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings, ClusterService clusterService) {
        this.ctiBaseUrl = CTI_API_URL.get(settings);
        this.clusterService = clusterService;

        log.debug("Settings loaded: {}", this.toString());
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
        return ClusterInfo.getClusterBaseUrl(this.clusterService);
    }
}
