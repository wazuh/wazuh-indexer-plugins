/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.config.reader;

public class ConfigReader {

    private String hostName;
    private int port;
    private String path;
    private String username;
    private String password;
    private static ConfigReader instance;

    private ConfigReader(String hostName, int port, String path, String username, String password) {
        this.hostName = hostName;
        this.port = port;
        this.path = path;
        this.username = username;
        this.password = password;
    }

    public static ConfigReader getInstance(String hostName, int port, String path, String username, String password) {
        if ( instance == null ) {
            instance = new ConfigReader(hostName, port, path, username, password);
        }
        return instance;
    }

    public String getHostName() {
        return hostName;
    }

    public int getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
