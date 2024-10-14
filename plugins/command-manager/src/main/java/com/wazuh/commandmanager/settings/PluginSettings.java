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

    private KeyStoreWrapper keyStoreWrapper = KeyStoreWrapper.create();
    private Environment environment;

    private PluginSettings(KeyStoreWrapper keyStoreWrapper) {
        // Singleton class, use getPluginSettings method instead of constructor
        this.keyStoreWrapper = keyStoreWrapper;
    }

    public static PluginSettings getInstance() {
        synchronized (PluginSettings.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            KeyStoreWrapper keyStoreWrapper1 = KeyStoreWrapper.create();
            INSTANCE = new PluginSettings(keyStoreWrapper1);
            return INSTANCE;
        }
    }

    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    public SecureSettings loadSecureSettings(SecureString secureSettingsPassword) throws CommandManagerSettingsException, GeneralSecurityException {
        try {
            //Open the keystore file
            this.keyStoreWrapper = KeyStoreWrapper.load( this.environment.configFile(),KEYSTORE_FILENAME);
            if ( this.keyStoreWrapper == null) {
                logger.info(CommandManagerSettingsException.keystoreNotExist( this.environment.configFile().toString()).getMessage());

                //Create keystore file if it doesn't exist
                this.keyStoreWrapper = KeyStoreWrapper.create();
                this.keyStoreWrapper.save( this.environment.configFile(), new char[0]);

            } else {
                // Decrypt the keystore using the password from the request
                this.keyStoreWrapper.decrypt(secureSettingsPassword.getChars());
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
        return  this.keyStoreWrapper;
    }

    public SecureSettings upgradeKeyStore( char[] password){
        try {
            KeyStoreWrapper.upgrade( this.keyStoreWrapper,  this.environment.configFile(), password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return  this.keyStoreWrapper;
    }

}