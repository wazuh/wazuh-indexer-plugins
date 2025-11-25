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
    @JsonProperty("token_type")
    private String tokenType;


    /**
     * Default constructor.
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
     * Getter for accessToken.
     * @return Access Token.
     */
    public String getAccessToken() {
        return this.accessToken;
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
