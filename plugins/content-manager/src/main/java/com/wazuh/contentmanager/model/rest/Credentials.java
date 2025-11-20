package com.wazuh.contentmanager.model.rest;

/**
 * Credentials model for managing CTI subscription credentials.
 */
public class Credentials {
    private String accessToken;
    private String tokenType;

    public Credentials() {
    }

    public Credentials(String accessToken, String tokenType) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
}
