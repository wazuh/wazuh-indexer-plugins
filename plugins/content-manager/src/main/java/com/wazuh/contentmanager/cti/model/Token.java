package com.wazuh.contentmanager.cti.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Token {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("expires_in")
    private Integer expiresIn;

    public Token() { }

    public String getAccessToken() {
        return this.accessToken;
    }

    public Integer getExpiresIn() {
        return this.expiresIn;
    }

    @Override
    public String toString() {
        return "{" +
            "accessToken='" + accessToken + '\'' +
            ", expiresIn=" + expiresIn +
            '}';
    }
}
