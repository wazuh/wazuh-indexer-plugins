/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;


public final class CommandManagerSettings {
//THE DEFINITIONS OF WHAT KEYS ARE NECESSARY ARE PENDING

    /** The access key (ie login id) for connecting to ec2. */
    public static final Setting<SecureString> ACCESS_KEY_SETTING = SecureSetting.secureString("command.manager.access_key", null);

    /** The secret key (ie password) for connecting to ec2. */
    public static final Setting<SecureString> SECRET_KEY_SETTING = SecureSetting.secureString("command.manager.secret_key", null);

    /** The session token for connecting to ec2. */
    public static final Setting<SecureString> SESSION_TOKEN_SETTING = SecureSetting.secureString("command.manager.session_token", null);

    /** The host name of a proxy to connect to ec2 through. */
    public static final Setting<String> PROXY_HOST_SETTING = Setting.simpleString("command.manager.proxy.host", Property.NodeScope);

    /** The port of a proxy to connect to ec2 through. */
    public static final Setting<Integer> PROXY_PORT_SETTING = Setting.intSetting("command.manager.proxy.port", 80, 0, 1 << 16, Property.NodeScope);

    /** An optional proxy host that requests to ec2 should be made through. */
    final String accessKey;

    /** The secret key (ie password) for connecting to ec2. */
    final String secretKey;

    /** The session token for connecting to ec2. */
    final String sessionToken;

    /** An optional proxy host that requests to ec2 should be made through. */
    final String proxyHost;

    /** The port number the proxy host should be connected on. */
    final int proxyPort;


    protected CommandManagerSettings(
            String accessKey,
            String secretKey,
            String sessionToken,
            String proxyHost,
            int proxyPort
    ) {
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.sessionToken = sessionToken;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;}

    /** Parse settings for a single client. */
    public static CommandManagerSettings getClientSettings(Settings settings) {
        //final AwsCredentials credentials = loadCredentials(settings); no estoy segura de si tendríamos que configurar algo asociado a AWS, supongo que no
            try(
                    SecureString accessKey = ACCESS_KEY_SETTING.get(settings);
                    SecureString secretKey = SECRET_KEY_SETTING.get(settings);
                    SecureString sessionToken = SESSION_TOKEN_SETTING.get(settings);
                    ){
                return new CommandManagerSettings(
                        accessKey.toString(),
                        secretKey.toString(),
                        sessionToken.toString(),
                        PROXY_HOST_SETTING.get(settings),
                        PROXY_PORT_SETTING.get(settings)
                );
        }
    }
}
