/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;

import com.wazuh.commandmanager.CommandManagerSettingsException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.opensearch.common.settings.KeyStoreWrapper;
import org.opensearch.common.settings.SecureSettings;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.env.Environment;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class PluginSettings {
    private static final Logger logger = (Logger) LogManager.getLogger(PluginSettings.class);

    private static PluginSettings INSTANCE;

    private static final String KEYSTORE_FILENAME = "wazuh-indexer.keystore";

    private static KeyStoreWrapper keyStoreWrapper = KeyStoreWrapper.create();
    private static Environment env;

    private PluginSettings() {
        // Singleton class, use getPluginSettings method instead of constructor
    }

    public static PluginSettings getPluginSettingsInstance() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (PluginSettings.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new PluginSettings();
            return INSTANCE;
        }
    }

    public void setEnv(Environment env) {
        PluginSettings.env = env;
    }

    static SecureSettings loadSecureSettings(SecureString secureSettingsPassword) throws CommandManagerSettingsException, GeneralSecurityException {
        try {
            //Open the keystore file
            keyStoreWrapper = KeyStoreWrapper.load(env.configFile(),KEYSTORE_FILENAME);
            if (keyStoreWrapper == null) {
                logger.info(CommandManagerSettingsException.keystoreNotExist(env.configFile().toString()).getMessage());

                //Create keystore file if it doesn't exist
                keyStoreWrapper = KeyStoreWrapper.create();
                keyStoreWrapper.save(env.configFile(), new char[0]);

            } else {
                // Decrypt the keystore using the password from the request
                keyStoreWrapper.decrypt(secureSettingsPassword.getChars());
                //Here TransportNodesReloadSecureSettingsAction reload the plugins, but our PLugin isn't ReloadablePlugin
                // final Settings settingsWithKeystore = Settings.builder().setSecureSettings(keyStoreWrapper).build();
            }
        } catch (IOException e) {
            throw new CommandManagerSettingsException(e);
         } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            secureSettingsPassword.close();
        }
        return keyStoreWrapper;
    }

    public SecureSettings upgradeKeyStore( char[] password){
        try {
            KeyStoreWrapper.upgrade(keyStoreWrapper, env.configFile(), password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return keyStoreWrapper;
    }

}