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
import org.opensearch.common.settings.KeyStoreWrapper;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.env.Environment;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

import com.wazuh.commandmanager.CommandManagerSettingsException;

public final class CommandManagerSettings {
    /** The access key (ie login id) for connecting to api. */
    public static final Setting<SecureString> KEYSTORE =
            SecureSetting.secureString("command.manager.keystore", null);

    /** The access key (ie login username) for connecting to api. */
    public static final Setting<SecureString> AUTH_USERNAME =
            SecureSetting.secureString("command.manager.auth.username", null);

    /** The secret key (ie password) for connecting to api. */
    public static final Setting<SecureString> AUTH_PASSWORD =
            SecureSetting.secureString("command.manager.auth.password", null);

    /** The uri for connecting to api. */
    public static final Setting<String> URI =
            SecureSetting.simpleString("command.manager.uri", Setting.Property.NodeScope);

    /** The auth type for connecting to api. */
    public static final Setting<String> AUTH_TYPE =
            Setting.simpleString("command.manager.auth.type", Setting.Property.NodeScope);

    private static final Logger log = LogManager.getLogger(CommandManagerSettings.class);

    /** The name of own keystore. */
    private static final String KEYSTORE_FILENAME =
            "opensearch.keystore"; // "wazuh-indexer.keystore";

    /** The access key (ie login username) for connecting to api. */
    final String keystore;

    /** The access key (ie login username) for connecting to api. */
    final String authUsername;

    /** The password for connecting to api. */
    final String authPassword;

    /** The uri for connecting to api. */
    final String uri;

    /** The auth type for connecting to api. */
    final String authType;

    private CommandManagerSettings(
            String keystore,
            String authUsername,
            String authPassword,
            String uri,
            String authType) {
        this.keystore = keystore;
        this.authUsername = authUsername;
        this.authPassword = authPassword;
        this.uri = uri;
        this.authType = authType;
        log.info("Plugin settings: {}", this.toString());
    }

    /** Parse settings for a single client. */
    public static CommandManagerSettings getSettings(
            Environment environment, SecureString secureSettingsPassword) {

        KeyStoreWrapper keyStoreWrapper = null;

        try {
            keyStoreWrapper = KeyStoreWrapper.load(environment.configFile(), KEYSTORE_FILENAME);
        } catch (IOException e) {
            log.error(
                    CommandManagerSettingsException.loadKeystoreFailed(
                                    environment.configFile().toAbsolutePath() + KEYSTORE_FILENAME)
                            .getMessage());
        }

        if (keyStoreWrapper == null) {
            log.error(
                    CommandManagerSettingsException.keystoreNotExist(KEYSTORE_FILENAME)
                            .getMessage());
            return null;
        } else {
            // Decrypt the keystore using the password from the request
            if (keyStoreWrapper.hasPassword()) {
                try {
                    keyStoreWrapper.decrypt(secureSettingsPassword.getChars());
                } catch (GeneralSecurityException | IOException e) {
                    log.error(
                            CommandManagerSettingsException.decryptKeystoreFailed(KEYSTORE_FILENAME)
                                    .getMessage());
                }
            }

            final Settings settings = Settings.builder().setSecureSettings(keyStoreWrapper).build();

            try (SecureString authUsername = AUTH_USERNAME.get(settings);
                    SecureString authPassword = AUTH_PASSWORD.get(settings); ) {
                return new CommandManagerSettings(
                        KEYSTORE_FILENAME,
                        authUsername.toString(),
                        authPassword.toString(),
                        URI.get(settings),
                        AUTH_TYPE.get(settings));
            }
        }
    }

    /** Parse settings for a single client. */
    public static CommandManagerSettings getSettings(Environment environment) {
        KeyStoreWrapper keyStoreWrapper = null;
        Path keystoreFile = Path.of(environment.configFile() + "/" + KEYSTORE_FILENAME);
        try {
            if (!Files.exists(keystoreFile)) {
                throw CommandManagerSettingsException.keystoreNotExist(
                        keystoreFile.toAbsolutePath().toString());
                // Path keyStorePath = Files.createFile(keystoreFile);
                // log.warn("CREADA KeyStoreWrapper en "+keyStorePath.toString());
            } else {
                log.warn(
                        "Por hacer load de KeyStoreWrapper en "
                                + environment.configFile().toString());
                keyStoreWrapper = KeyStoreWrapper.load(environment.configFile(), KEYSTORE_FILENAME);
            }
        } catch (Exception e) {
            log.error(
                    CommandManagerSettingsException.loadKeystoreFailed(keystoreFile.toString())
                            .getMessage());
        }

        if (keyStoreWrapper == null) {
            log.error(
                    CommandManagerSettingsException.keystoreNotExist(keystoreFile.toString())
                            .getMessage());
            return null;
        } else {
            // Decrypt the keystore using the password from the request
            try {
                keyStoreWrapper.decrypt(new char[0]);
            } catch (GeneralSecurityException | IOException e) {
                log.error(
                        CommandManagerSettingsException.decryptKeystoreFailed(KEYSTORE_FILENAME)
                                .getMessage());
            }

            final Settings settings = Settings.builder().setSecureSettings(keyStoreWrapper).build();

            try (SecureString authUsername = AUTH_USERNAME.get(settings);
                    SecureString authPassword = AUTH_PASSWORD.get(settings); ) {
                return new CommandManagerSettings(
                        KEYSTORE_FILENAME,
                        authUsername.toString(),
                        authPassword.toString(),
                        URI.get(settings),
                        AUTH_TYPE.get(settings));
            }
        }
    }

    @Override
    public String toString() {
        return "CommandManagerSettings{"
                + "keystore='"
                + keystore
                + '\''
                + ", authUsername='"
                + authUsername
                + '\''
                + ", authPassword='"
                + authPassword
                + '\''
                + ", uri='"
                + uri
                + '\''
                + ", authType='"
                + authType
                + '\''
                + '}';
    }
}
