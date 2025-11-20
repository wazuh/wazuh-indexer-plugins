package com.wazuh.contentmanager.model.rest;

public class Credentials {
    private static volatile Credentials instance;

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
    public static Credentials createOrUpdate(String accessToken, String tokenType) {
        Credentials newInstance = new Credentials(accessToken, tokenType);
        instance = newInstance;
        return newInstance;
    }

    /**
     * Gets the singleton instance.
     *
     * @return the singleton instance, or null if not yet created
     */
    public static Credentials getInstance() {
        if (instance == null) {
            throw new IllegalStateException("Credentials have not been initialized.");
        }
        return instance;
    }

    public String getAccessToken() { return accessToken; }
    public String getTokenType() { return tokenType; }
}
