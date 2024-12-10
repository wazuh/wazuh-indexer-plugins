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
import org.opensearch.common.settings.Settings;

import java.io.IOException;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class PluginSettings2 {
    private static final Logger log = LogManager.getLogger(PluginSettings2.class);

    private static PluginSettings2 instance;

    public static final String JDK_CA_CERT_PATH = "jdkCACertPath";
    public static final String WAZUH_INDEXER_CA_CERT_PATH = "wazuhIndexerCACertPath";
    public static final String CA_CERT_ALIAS = "caCertAlias";

    private static final String DEFAULT_JDK_CA_CERT_PATH =
            "/usr/share/wazuh-indexer/jdk/lib/security/cacerts";
    private static final String DEFAULT_WAZUH_INDEXER_CA_CERT_PATH =
            "/etc/wazuh-indexer/certs/root-ca.pem";
    private static final String DEFAULT_CA_CERT_ALIAS = "wazuh-root-ca";

    private static String jdkCACertPath;
    private static String wazuhIndexerCACertPath;
    private static String caCertAlias;

    /** Private default constructor */
    private PluginSettings2() {
        String configDirName =
                "/home/mcasas/Documentos/Proyectos/wazuh-indexer-plugins/plugins/command-manager/src/main/resources/command-manager-settings.yml"; // System.getProperty("wazuh.indexer.path.conf");
        log.info("configDirName: {}", configDirName);
        if (configDirName != null) {
            Path defaultSettingYmlFile = Path.of(configDirName);
            log.info("defaultSettingYmlFile: {}", defaultSettingYmlFile);

            Settings settings =
                    AccessController.doPrivileged(
                            (PrivilegedAction<Settings>)
                                    () -> {
                                        try {
                                            return Settings.builder()
                                                    .loadFromPath(defaultSettingYmlFile)
                                                    .build();
                                        } catch (IOException exception) {
                                            log.warn(
                                                    "Failed to load settings from {} message:{}",
                                                    defaultSettingYmlFile.toAbsolutePath(),
                                                    exception.getMessage());
                                        }
                                        return null;
                                    });

            jdkCACertPath =
                    (settings != null && settings.get(JDK_CA_CERT_PATH) != null)
                            ? String.valueOf(settings.get(JDK_CA_CERT_PATH))
                            : DEFAULT_JDK_CA_CERT_PATH;

            wazuhIndexerCACertPath =
                    (settings != null && settings.get(WAZUH_INDEXER_CA_CERT_PATH) != null)
                            ? String.valueOf(settings.get(WAZUH_INDEXER_CA_CERT_PATH))
                            : DEFAULT_WAZUH_INDEXER_CA_CERT_PATH;

            caCertAlias =
                    (settings != null && settings.get(CA_CERT_ALIAS) != null)
                            ? String.valueOf(settings.get(CA_CERT_ALIAS))
                            : DEFAULT_CA_CERT_ALIAS;

            log.info("Plugin created with the keystore information.");
        }
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings2#instance}
     */
    public static PluginSettings2 getInstance() {
        if (PluginSettings2.instance == null) {
            instance = new PluginSettings2(); // Singleton instance
        }
        return instance;
    }

    public static String getJdkCACertPath() {
        return jdkCACertPath;
    }

    public static String getWazuhIndexerCACertPath() {
        return wazuhIndexerCACertPath;
    }

    public static String getCaCertAlias() {
        return caCertAlias;
    }
}
