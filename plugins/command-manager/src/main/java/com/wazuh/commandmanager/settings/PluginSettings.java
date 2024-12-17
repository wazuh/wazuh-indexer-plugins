/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;

import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;

import java.net.URISyntaxException;

import reactor.util.annotation.NonNull;

public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);
    private static PluginSettings instance;

    /** The access key (ie login username) for connecting to api. */
    public static final Setting<SecureString> M_API_AUTH_USERNAME =
            SecureSetting.secureString("m_api.auth.username", null);

    /** The secret key (ie password) for connecting to api. */
    public static final Setting<SecureString> M_API_AUTH_PASSWORD =
            SecureSetting.secureString("m_api.auth.password", null);

    /** The uri for connecting to api. */
    public static final Setting<SecureString> M_API_URI =
            SecureSetting.secureString("m_api.uri", null);

    /** The key of the path where is located the wazuh indexer CA certificate. */
    public static final Setting<String> WAZUH_INDEXER_CA_CERT_PATH =
            Setting.simpleString("ssl.http.pemtrustedcas_filepath", Setting.Property.NodeScope);

    /** The default value to path where is located the wazuh indexer CA certificate. */
    private static final String DEFAULT_WAZUH_INDEXER_CA_CERT_PATH =
            "/etc/wazuh-indexer/certs/root-ca.pem";

    /** The access key (ie login username) for connecting to api. */
    private final SecureString authUsername;

    /** The password for connecting to api. */
    private final SecureString authPassword;

    /** The uri for connecting to api. */
    private final SecureString uri;

    /** The path where is located the wazuh indexer CA certificate. */
    private final String wazuhIndexerCACertPath;

    /** Private default constructor */
    private PluginSettings(@NonNull final Settings settings) {
        log.info("Plugin created with the keystore information.");

        this.authUsername = M_API_AUTH_USERNAME.get(settings);
        this.authPassword = M_API_AUTH_PASSWORD.get(settings);
        this.uri = M_API_URI.get(settings);

        this.wazuhIndexerCACertPath =
                (settings != null && WAZUH_INDEXER_CA_CERT_PATH.get(settings) != null)
                        ? WAZUH_INDEXER_CA_CERT_PATH.get(settings)
                        : DEFAULT_WAZUH_INDEXER_CA_CERT_PATH;
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @return {@link PluginSettings#instance}
     */
    public static PluginSettings getInstance(@NonNull final Settings settings) {
        if (PluginSettings.instance == null) {
            instance = new PluginSettings(settings);
        }
        return instance;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#instance}
     */
    public static PluginSettings getInstance() {
        if (PluginSettings.instance == null) {
            throw new IllegalStateException("Plugin settings have not been initialized.");
        }
        return instance;
    }

    public String getAuthPassword() {
        return this.authPassword.toString();
    }

    public String getAuthUsername() {
        return this.authUsername.toString();
    }

    public String getUri() {
        return this.uri.toString();
    }

    public String getUri(String path) throws URISyntaxException {
        return new URIBuilder(getUri()).setPath(path).build().toString();
    }


    public String getWazuhIndexerCACertPath() {
        return wazuhIndexerCACertPath;
    }

    @Override
    public String toString() {
        return "PluginSettings{"
                + "authUsername='"
                + getAuthUsername()
                + '\''
                + ", authPassword='"
                + getAuthUsername()
                + '\''
                + ", uri='"
                + getUri()
                + '\''
                + ", wazuhIndexerCACertPath='"
                + getWazuhIndexerCACertPath()
                + '\''
                + '}';
    }
}
