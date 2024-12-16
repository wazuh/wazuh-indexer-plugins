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

    /** The access key (ie login username) for connecting to api. */
    public static final Setting<String> M_API_AUTH_USERNAME =
            Setting.simpleString("m_api.auth.username", Setting.Property.NodeScope, Setting.Property.Filtered);

    /** The secret key (ie password) for connecting to api. */
    public static final Setting<String> M_API_AUTH_PASSWORD =
            Setting.simpleString("m_api.auth.password", Setting.Property.NodeScope, Setting.Property.Filtered);

    /** The uri for connecting to api. */
    public static final Setting<String> M_API_URI =
            Setting.simpleString("m_api.uri", Setting.Property.NodeScope, Setting.Property.Filtered);

    private static final Logger log = LogManager.getLogger(PluginSettings.class);
    private static PluginSettings instance;

    /** The access key (ie login username) for connecting to api. */
    private final String authUsername;

    /** The password for connecting to api. */
    private final String authPassword;

    /** The uri for connecting to api. */
    private final String uri;

    /** Private default constructor */
    private PluginSettings(@NonNull final Settings settings) {
        log.info("Plugin created with the keystore information.");

        this.authUsername = M_API_AUTH_USERNAME.get(settings);
        this.authPassword = M_API_AUTH_PASSWORD.get(settings);
        this.uri = M_API_URI.get(settings);
        log.info("[SETTINGS] Username: {}", this.authUsername);
        log.info("[SETTINGS] URI: {}", this.uri);
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
        return this.authPassword.toString();
    }

    public String getAuthUsername() {
        return this.authUsername.toString();
    }

    public String getUri() {
        return this.uri.toString();
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
