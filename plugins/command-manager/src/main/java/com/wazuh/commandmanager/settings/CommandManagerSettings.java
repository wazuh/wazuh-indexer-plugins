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

    /** The access key (ie login username) for connecting to api. */
    public static final Setting<SecureString> M_API_USERNAME =
            SecureSetting.secureString("m.api.username", null);

    /** The secret key (ie password) for connecting to api. */
    public static final Setting<SecureString> M_API_PASSWORD =
            SecureSetting.secureString("m.api.password", null);

    /** The uri for connecting to api. */
    public static final Setting<SecureString> M_API_URI =
            SecureSetting.secureString("m.api.uri", null);

    private static final Logger log = LogManager.getLogger(CommandManagerSettings.class);

    /** The name of own keystore. */
    private static final String KEYSTORE_FILENAME = "opensearch.keystore";

    /** The access key (ie login username) for connecting to api. */
    final String authUsername;

    /** The password for connecting to api. */
    final String authPassword;

    /** The uri for connecting to api. */
    final String uri;

    private final Settings settings;

    private CommandManagerSettings(
            String authUsername, String authPassword, String uri, Settings settings) {
        this.authUsername = authUsername;
        this.authPassword = authPassword;
        this.uri = uri;
        this.settings = settings;
        log.info("CommandManagerSettings created ");
    }

    /** Parse settings for a single client. */
    public static CommandManagerSettings getSettings(
            Environment environment, SecureString secureSettingsPassword) {
        KeyStoreWrapper keyStoreWrapper = null;
        Path keystoreFile = Path.of(environment.configFile() + "/" + KEYSTORE_FILENAME);
        try {
            if (!Files.exists(keystoreFile)) {
                log.error(
                        CommandManagerSettingsException.keystoreNotExist(
                                        keystoreFile.toAbsolutePath().toString())
                                .getMessage());
                return null;
            } else {
                keyStoreWrapper = KeyStoreWrapper.load(environment.configFile(), KEYSTORE_FILENAME);
                log.info("Keystore load: " + keystoreFile.toAbsolutePath().toString());
            }
        } catch (Exception e) {
            log.error(
                    CommandManagerSettingsException.loadKeystoreFailed(keystoreFile.toString())
                            .getMessage());
            return null;
        }

        if (keyStoreWrapper == null) {
            log.error(
                    CommandManagerSettingsException.keystoreNotExist(keystoreFile.toString())
                            .getMessage());
            return null;
        } else {
            // Decrypt the keystore using the password from the request
            try {
                log.info("Decrypting the keystore.");
                if (secureSettingsPassword == null || secureSettingsPassword.length() == 0) {
                    keyStoreWrapper.decrypt(new char[0]);
                } else {
                    keyStoreWrapper.decrypt(secureSettingsPassword.getChars());
                }
            } catch (GeneralSecurityException | IOException e) {
                log.error(
                        CommandManagerSettingsException.decryptKeystoreFailed(KEYSTORE_FILENAME)
                                .getMessage());
            }

            final Settings settings = Settings.builder().setSecureSettings(keyStoreWrapper).build();
            log.info("Settings created with the keystore information.");

            try (SecureString authUsername = M_API_USERNAME.get(settings);
                    SecureString authPassword = M_API_PASSWORD.get(settings);
                    SecureString uri = M_API_URI.get(settings); ) {
                return new CommandManagerSettings(
                        authUsername.toString(),
                        authPassword.toString(),
                        uri.toString(),
                        environment.settings());
            }
        }
    }

    public String getAuthPassword() {
        return M_API_PASSWORD.get(this.settings).toString();
    }

    public String getAuthUsername() {
        return M_API_USERNAME.get(this.settings).toString();
    }

    public String getUri() {
        return this.uri;
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
