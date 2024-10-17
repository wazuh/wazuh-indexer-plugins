/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;
import com.wazuh.commandmanager.CommandManagerSettingsException;
import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.KeyStoreWrapper;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.env.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;

public final class CommandManagerSettings {
    /**
     * The name of own keystore.
     */
    private static final String KEYSTORE_FILENAME = "wazuh-indexer.keystore";

    /**
     * The access key (ie login id) for connecting to api.
     */
    public static final Setting<SecureString> KEYSTORE = SecureSetting.secureString("command.manager.keystore", null);

    /**
     * The access key (ie login username) for connecting to api.
     */
    public static final Setting<SecureString> AUTH_USERNAME = SecureSetting.secureString("command.manager.auth.username", null);

    /**
     * The secret key (ie password) for connecting to api.
     */
    public static final Setting<SecureString> AUTH_PASSWORD = SecureSetting.secureString("command.manager.auth.password", null);

    /**
     * The uri for connecting to api.
     */
    public static final Setting<String> URI = SecureSetting.simpleString("command.manager.uri", Setting.Property.NodeScope);

    /**
     * The auth type for connecting to api.
     */
    public static final Setting<String> AUTH_TYPE = Setting.simpleString("command.manager.auth.type", Setting.Property.NodeScope);
    private static final Logger log = LoggerFactory.getLogger(CommandManagerSettings.class);

    /**
     * The access key (ie login username) for connecting to api.
     */
    final String keystore;

    /**
     * The access key (ie login username) for connecting to api.
     */
    final String authUsername;

    /**
     * The password for connecting to api.
     */
    final String authPassword;

    /**
     * The uri for connecting to api.
     */
    final String uri;

    /**
     * The auth type for connecting to api.
     */
    final String authType;

    private Environment environment;


    protected CommandManagerSettings(
            String keystore,
            String authUsername,
            String authPassword,
            String uri,
            String authType
    ) {
        this.keystore = keystore;
        this.authUsername = authUsername;
        this.authPassword = authPassword;
        this.uri = uri;
        this.authType = authType;
    }

    /**
     * Parse settings for a single client.
     */
    public static CommandManagerSettings getSettings(Environment environment, SecureString secureSettingsPassword) {

        //Environment environment = new Environment(null, PathUtils.get(System.getProperty("user.dir")));
        KeyStoreWrapper keyStoreWrapper = null;

        try {
            keyStoreWrapper = KeyStoreWrapper.load(environment.configFile(), KEYSTORE_FILENAME);
        } catch (IOException e) {
            log.error(CommandManagerSettingsException.loadKeystoreFailed(environment.configFile().toAbsolutePath().toString() + KEYSTORE_FILENAME).getMessage());
        }

        if (keyStoreWrapper == null) {
            log.error(CommandManagerSettingsException.keystoreNotExist(KEYSTORE_FILENAME).getMessage());
            return null;
        } else {
            // Decrypt the keystore using the password from the request
            if (keyStoreWrapper.hasPassword()) {
                try {
                    keyStoreWrapper.decrypt(secureSettingsPassword.getChars());
                } catch (GeneralSecurityException | IOException e) {
                    log.error(CommandManagerSettingsException.decryptKeystoreFailed(KEYSTORE_FILENAME).getMessage());
                }
            }

            final Settings settings = Settings.builder().setSecureSettings(keyStoreWrapper).build();

            try (
                    SecureString authUsername = AUTH_USERNAME.get(settings);
                    SecureString authPassword = AUTH_PASSWORD.get(settings);
            ) {
                return new CommandManagerSettings(
                        KEYSTORE_FILENAME,
                        authUsername.toString(),
                        authPassword.toString(),
                        URI.get(settings),
                        AUTH_TYPE.get(settings)
                );
            }
        }
    }

    /**
     * Parse settings for a single client.
     */
    public static CommandManagerSettings getSettings(Environment environment) {

        KeyStoreWrapper keyStoreWrapper = null;

        try {
            keyStoreWrapper = KeyStoreWrapper.load(environment.configFile(), KEYSTORE_FILENAME);
        } catch (IOException e) {
            log.error(CommandManagerSettingsException.loadKeystoreFailed(environment.configFile().toAbsolutePath().toString() + KEYSTORE_FILENAME).getMessage());
        }

        if (keyStoreWrapper == null) {
            log.error(CommandManagerSettingsException.keystoreNotExist(KEYSTORE_FILENAME).getMessage());
            return null;
        } else {
            // Decrypt the keystore using the password from the request
            if (keyStoreWrapper.hasPassword()) {
                try {
                    keyStoreWrapper.decrypt(new char[0]);
                } catch (GeneralSecurityException | IOException e) {
                    log.error(CommandManagerSettingsException.decryptKeystoreFailed(KEYSTORE_FILENAME).getMessage());
                }
            }
            final Settings settings =Settings.builder().setSecureSettings(keyStoreWrapper).build();

            try (
                    SecureString authUsername = AUTH_USERNAME.get(settings);
                    SecureString authPassword = AUTH_PASSWORD.get(settings);
            ) {
                return new CommandManagerSettings(
                        KEYSTORE_FILENAME,
                        authUsername.toString(),
                        authPassword.toString(),
                        URI.get(settings),
                        AUTH_TYPE.get(settings)
                );
            }
        }
    }

}

