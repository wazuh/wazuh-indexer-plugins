package com.wazuh.commandmanager.config.reader;

public class ConfigReader {

    String hostName;
    int port;
    String path;
    String username;
    String password;

    public ConfigReader() {
        // Hardcoded output API values for testing purposes
        //this.ipAddress = "127.0.0.1";
        //this.port = 5000;
        //this.path = "/test/post";
        //this.username = "admin";
        //this.password = "admin";
        this.hostName = "jsonplaceholder.typicode.com";
        this.port = 80;
        this.path = "/posts/1";
        this.username = "admin";
        this.password = "admin";
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
