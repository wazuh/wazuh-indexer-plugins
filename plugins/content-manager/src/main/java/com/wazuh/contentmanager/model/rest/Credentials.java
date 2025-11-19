package com.wazuh.contentmanager.model.rest;

public class Credentials {
    private static Credentials instance;

    private String accessToken;
    private String tokenType;

    private Credentials(String accessToken, String tokenType) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
    }

    /**
     * Creates or updates the singleton instance with new credentials.
     *
     * @param accessToken the access token
     * @param tokenType the token type (e.g., "Bearer")
     * @return the singleton instance
     */
    public static synchronized Credentials createOrUpdate(String accessToken, String tokenType) {
        if (instance == null) {
            instance = new Credentials(accessToken, tokenType);
        } else {
            instance.accessToken = accessToken;
            instance.tokenType = tokenType;
        }
        return instance;
    }

    /**
     * Gets the singleton instance.
     *
     * @return the singleton instance, or null if not yet created
     */
    public static synchronized Credentials getInstance() {
        return instance;
    }

    public String getAccessToken() { return accessToken; }
    public String getTokenType() { return tokenType; }

    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
}
