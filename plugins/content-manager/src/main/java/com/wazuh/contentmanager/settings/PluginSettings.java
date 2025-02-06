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
import org.opensearch.common.settings.Settings;

import reactor.util.annotation.NonNull;

/** Singleton class to manage the plugin's settings. */
public class PluginSettings {

    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings) {
        log.info("Plugin created with the keystore information.");
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @param settings as obtained in createComponents.
     * @return {@link PluginSettings#INSTANCE}
     */
    public static PluginSettings getInstance(@NonNull final Settings settings) {
        if (INSTANCE == null) {
            synchronized (PluginSettings.class) {
                if (INSTANCE == null) {
                    INSTANCE = new PluginSettings(settings);
                }
            }
        }
        return INSTANCE;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#INSTANCE}
     */
    public static PluginSettings getInstance() {
        if (PluginSettings.INSTANCE == null) {
            throw new IllegalStateException("Plugin settings have not been initialized.");
        }
        return INSTANCE;
    }
}
