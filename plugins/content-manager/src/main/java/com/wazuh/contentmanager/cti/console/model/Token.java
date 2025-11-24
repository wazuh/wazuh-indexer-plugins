package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *  CTI token DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Token {
    @JsonProperty("access_token")
    private String accessToken;

    /**
     * Default constructor.
     */
    public Token() { }

    /**
     * Getter for accessToken.
     * @return Access Token.
     */
    public String getAccessToken() {
        return this.accessToken;
    }


    @Override
    public String toString() {
        return "Token{" +
            "accessToken='" + accessToken + '\'' +
            '}';
    }
}
