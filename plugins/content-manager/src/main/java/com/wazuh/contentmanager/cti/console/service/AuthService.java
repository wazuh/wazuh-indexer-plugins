package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.TokenListener;
import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.model.Subscription;

/**
 * Service interface for handling authentication with the CTI Console.
 * Manages the retrieval of permanent tokens and resource-specific tokens.
 */
public interface AuthService extends ClosableHttpClient {

    /**
     * Retrieves a permanent authentication token based on the provided subscription details.
     *
     * @param subscription The subscription details containing client ID and device code.
     * @return The permanent {@link Token}, or null if retrieval fails.
     */
    Token getToken(Subscription subscription);

    /**
     * Exchanges a permanent token for a resource-specific token.
     *
     * @param token The permanent authentication token.
     * @param resource The identifier of the resource to access.
     * @return A resource-specific {@link Token}, or null if retrieval fails.
     */
    Token getResourceToken(Token token, String resource);

    /**
     * Registers a listener to receive updates when the token changes.
     *
     * @param listener The {@link TokenListener} to add.
     */
    void addListener(TokenListener listener);
}
