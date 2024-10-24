/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.env.Environment;


public class CommandManagerSettings {

    /** The access key (ie login username) for connecting to api. */
    public static final Setting<SecureString> M_API_AUTH_USERNAME =
            SecureSetting.secureString("m_api.auth.username", null);

    /** The secret key (ie password) for connecting to api. */
    public static final Setting<SecureString> M_API_AUTH_PASSWORD =
            SecureSetting.secureString("m_api.auth.password", null);

    /** The uri for connecting to api. */
    public static final Setting<SecureString> M_API_URI =
            SecureSetting.secureString("m_api.uri", null);

    /** The access key (ie login username) for connecting to api. */
    private final String authUsername;

    /** The password for connecting to api. */
    private final String authPassword;

    /** The uri for connecting to api. */
    private final String uri;

    private static final Logger log = LogManager.getLogger(CommandManagerSettings.class);
    private static CommandManagerSettings instance;
    private final Settings settings;

    /** Private default constructor */
    private CommandManagerSettings(
            String authUsername, String authPassword, String uri, Settings settings) {
        this.authUsername = authUsername;
        this.authPassword = authPassword;
        this.uri = uri;
        this.settings = settings;
        log.info("CommandManagerSettings created ");
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link CommandManagerSettings#instance}
     */
    public static CommandManagerSettings getInstance(Environment environment) {
        if (CommandManagerSettings.instance == null) {
            instance = CommandManagerSettings.getSettings(environment);
        }
        return CommandManagerSettings.instance;
    }

    /** Parse settings for a single client. */
    public static CommandManagerSettings getSettings(
            Environment environment) {

        final Settings settings = environment.settings();
        assert settings != null;
        log.info("Settings created with the keystore information.");

            try (SecureString authUsername = M_API_AUTH_USERNAME.get(settings);
                 SecureString authPassword = M_API_AUTH_PASSWORD.get(settings);
                 SecureString uri = M_API_URI.get(settings); ) {
                return new CommandManagerSettings(
                        authUsername.toString(),
                        authPassword.toString(),
                        uri.toString(),
                        settings);
            }
        }


    public String getAuthPassword() {
        return authPassword;
    }

    public String getAuthUsername() {
        return authUsername;
    }

    public String getUri() {
        return uri;
    }

    @Override
    public String toString() {
        return "CommandManagerSettings{"
                + " authUsername='"
                + authUsername
                + '\''
                + ", authPassword='"
                + authPassword
                + '\''
                + ", uri='"
                + uri
                + '\''
                + '}';
    }
}
