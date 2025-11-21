package com.wazuh.contentmanager.model.rest;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Token model for managing CTI subscription credentials.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Token {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("expires_in")
    private Integer expiresIn;
    @JsonProperty("token_type")
    private String tokenType;

    public Token() { }

    public Token(String accessToken, String tokenType) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public Integer getExpiresIn() {
        return this.expiresIn;
    }

    public void setExpiresIn(Integer expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getTokenType() {
        return this.tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    @Override
    public String toString() {
        return "{" +
            "accessToken='" + accessToken + '\'' +
            ", expiresIn=" + expiresIn +
            ", tokenType='" + tokenType + '\'' +
            '}';
    }
}