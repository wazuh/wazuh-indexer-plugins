/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
 */
package com.wazuh.commandmanager.settings;

public class CommandManagerSettingsException extends Exception {

    // Constructor that accepts a message
    public CommandManagerSettingsException(String message) {
        super(message);
    }

    // Exception for the case when load keystore failed
    public static CommandManagerSettingsException loadSettingsFailed(
            String keyStorePath, String errorMessage) {
        return new CommandManagerSettingsException(
                "Load settings from: " + keyStorePath + " failed. Error: " + errorMessage);
    }

    // Exception for the case when reload plugin with the keystore failed
    public static CommandManagerSettingsException reloadPluginFailed(String pluginName) {
        return new CommandManagerSettingsException("Reload failed for plugin: " + pluginName);
    }
}
