/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager;

public class CommandManagerSettingsException extends Exception {

    // Default constructor
    public CommandManagerSettingsException() {
        super();
    }

    // Constructor that accepts a message
    public CommandManagerSettingsException(String message) {
        super(message);
    }

    // Constructor that accepts a message and a cause
    public CommandManagerSettingsException(String message, Throwable cause) {
        super(message, cause);
    }

    // Constructor that accepts a cause
    public CommandManagerSettingsException(Throwable cause) {
        super(cause);
    }

    // Exception for the case when the keystore does not exist
    public static CommandManagerSettingsException keystoreNotExist(String keystorePath) {
        return new CommandManagerSettingsException(
                "The keystore does not exist at the path: " + keystorePath);
    }

    // Exception for the case when the keystore is empty
    public static CommandManagerSettingsException keystoreEmpty(String keystorePath) {
        return new CommandManagerSettingsException(
                "The keystore is empty at the path: " + keystorePath);
    }

    // Exception for the case when load keystore failed
    public static CommandManagerSettingsException loadKeystoreFailed(String keyStorePath) {
        return new CommandManagerSettingsException("Load keystore: " + keyStorePath + " failed.");
    }

    // Exception for the case when load keystore failed
    public static CommandManagerSettingsException decryptKeystoreFailed(String keyStorePath) {
        return new CommandManagerSettingsException(
                "Decrypt keystore: " + keyStorePath + " failed.");
    }

    // Exception for the case when reload plugin with the keystore failed
    public static CommandManagerSettingsException reloadPluginFailed(String pluginName) {
        return new CommandManagerSettingsException("Reload failed for plugin: " + pluginName);
    }
}
