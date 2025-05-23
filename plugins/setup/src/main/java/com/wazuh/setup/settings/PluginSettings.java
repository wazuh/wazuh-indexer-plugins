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
package com.wazuh.setup.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

import reactor.util.annotation.NonNull;

/** Plugin settings */
public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    // Settings default values
    private static final Integer DEFAULT_CLIENT_TIMEOUT = 30;

    // Client class methods' timeout in seconds
    public static final Setting<Integer> CLIENT_TIMEOUT =
            Setting.intSetting(
                    "setup.client.timeout",
                    DEFAULT_CLIENT_TIMEOUT,
                    5,
                    120,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    private final Integer timeout;

    private static PluginSettings instance;

    /** Private default constructor */
    private PluginSettings(@NonNull final Settings settings) {
        this.timeout = CLIENT_TIMEOUT.get(settings);
        log.debug("Settings loaded: {}", this.toString());
    }


    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @param settings
     * @return {@link PluginSettings#instance}
     */
    public static synchronized PluginSettings getInstance(@NonNull final Settings settings) {
        if (instance == null) {
            instance = new PluginSettings(settings);
        }
        return instance;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#instance}
     */
    public static synchronized PluginSettings getInstance() {
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

    @Override
    public String toString() {
        return "PluginSettings{" +
            "timeout=" + timeout +
            '}';
    }
}
