/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.config.reader;

public class ConfigReader {

    String hostName;
    int port;
    String path;
    String username;
    String password;

    public ConfigReader() {
        this.hostName = "jsonplaceholder.typicode.com";
        this.port = 80;
        this.path = "/posts/1";
        this.username = "admin";
        this.password = "admin";
    }

    public ConfigReader(String hostName, int port, String path, String username, String password) {
        this.hostName = hostName;
        this.port = port;
        this.path = path;
        this.username = username;
        this.password = password;
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
