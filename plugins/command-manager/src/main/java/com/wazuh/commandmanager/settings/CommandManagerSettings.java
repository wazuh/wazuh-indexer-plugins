/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;


public final class CommandManagerSettings {

    /** The access key (ie login id) for connecting to api. */
    public static final Setting<SecureString> KEYSTORE = SecureSetting.secureString("command.manager.keystore", null);

    /** The access key (ie login username) for connecting to api. */
    public static final Setting<SecureString> AUTH_USERNAME = SecureSetting.secureString("command.manager.auth.username", null);

    /** The secret key (ie password) for connecting to api. */
    public static final Setting<SecureString> AUTH_PASSWORD = SecureSetting.secureString("command.manager.auth.password", null);

    /** The uri for connecting to api. */
    public static final Setting<String> URI = SecureSetting.simpleString("command.manager.uri", Setting.Property.NodeScope);

    /** The auth type for connecting to api. */
    public static final Setting<String> AUTH_TYPE = Setting.simpleString("command.manager.auth.type", Setting.Property.NodeScope);

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
        this.authType = authType;}

    /** Parse settings for a single client. */
    public static CommandManagerSettings getClientSettings(Settings settings) {
            try(
                    SecureString keystore = KEYSTORE.get(settings);
                    SecureString authUsername = AUTH_USERNAME.get(settings);
                    SecureString authPassword = AUTH_PASSWORD.get(settings);
                    ){
                return new CommandManagerSettings(
                        keystore.toString(),
                        authUsername.toString(),
                        authPassword.toString(),
                        URI.get(settings),
                        AUTH_TYPE.get(settings)
                );
        }
    }
}
