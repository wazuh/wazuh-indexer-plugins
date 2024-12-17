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
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;

import reactor.util.annotation.NonNull;

/** Singleton class to manage the plugin's settings. */
public class PluginSettings {

    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    /** The access key (ie login username) for connecting to api. */
    public static final Setting<SecureString> M_API_AUTH_USERNAME =
            SecureSetting.secureString("m_api.auth.username", null);

    /** The secret key (ie password) for connecting to api. */
    public static final Setting<SecureString> M_API_AUTH_PASSWORD =
            SecureSetting.secureString("m_api.auth.password", null);

    /** The uri for connecting to api. */
    public static final Setting<SecureString> M_API_URI =
            SecureSetting.secureString("m_api.uri", null);

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /** The access key (ie login username) for connecting to api. */
    private final SecureString authUsername;

    /** The password for connecting to api. */
    private final SecureString authPassword;

    /** The uri for connecting to api. */
    private final SecureString uri;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings) {
        log.info("Plugin created with the keystore information.");

        this.authUsername = M_API_AUTH_USERNAME.get(settings);
        this.authPassword = M_API_AUTH_PASSWORD.get(settings);
        this.uri = M_API_URI.get(settings);
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @param settings as obtained in createComponents.
     * @return {@link PluginSettings#INSTANCE}
     */
    public static PluginSettings getInstance(@NonNull final Settings settings) {
        if (PluginSettings.INSTANCE == null) {
            INSTANCE = new PluginSettings(settings);
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

    /**
     * Get M_API password.
     *
     * @return M_API password.
     */
    public String getAuthPassword() {
        return this.authPassword.toString();
    }

    /**
     * Get M_API username.
     *
     * @return M_API username.
     */
    public String getAuthUsername() {
        return this.authUsername.toString();
    }

    /**
     * M_API URL. For example: https://127.0.0.1:55000.
     *
     * @return M_API URL.
     */
    public String getUri() {
        return this.uri.toString();
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
