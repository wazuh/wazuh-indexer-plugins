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
    @JsonProperty("token_type")
    private String tokenType;

    /**
     * Default constructor for frameworks that require a no-arg constructor
     */
    public Token() { }

    /**
     * Creates a Token instance with the provided access token and token type.
     *
     * @param accessToken the access token issued by the CTI provider
     * @param tokenType   the type of the token (e.g., "Bearer")
     */
    public Token(String accessToken, String tokenType) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
    }

    /**
     * Returns the access token string.
     *
     * @return the access token, may be null
     */
    public String getAccessToken() {
        return this.accessToken;
    }

    /**
     * Sets the access token string.
     *
     * @param accessToken the access token to set
     */
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * Returns the token type (e.g., "Bearer").
     *
     * @return the token type string, may be null
     */
    public String getTokenType() {
        return this.tokenType;
    }

    /**
     * Sets the token type for this token.
     *
     * @param tokenType the token type to set
     */
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Returns a compact string representation of this Token for logging.
     *
     * @return string representation containing accessToken and tokenType
     */
    @Override
    public String toString() {
        return "Token{" +
                "accessToken='" + accessToken + '\'' +
                ", tokenType='" + tokenType + '\'' +
                '}';
    }
}