package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.TokenListener;
import com.wazuh.contentmanager.cti.console.model.Token;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeoutException;


/**
 * Implementation of the AuthService interface.
 */
public class AuthServiceImpl extends AbstractService implements AuthService {
    private static final Logger log = LogManager.getLogger(AuthServiceImpl.class);
    private final List<TokenListener> listeners;

    /**
     * Default constructor
     */
    public AuthServiceImpl() {
        super();
        this.listeners = new ArrayList<>();
    }

    /**
     * Obtains a permanent token for the instance from CTI Console.
     * @param clientId unique client identifier for the instance.
     * @param deviceCode unique device code provided by the CTI Console during the registration of the instance.
     * @return access token.
     */
    // TODO replace parameters with SubscriptionModel from https://github.com/wazuh/wazuh-indexer-plugins/pull/662
    @Override
    public Token getToken(String clientId, String deviceCode) {
        try {
            // Perform request
            SimpleHttpResponse response = this.client.getToken(clientId, deviceCode);

            if (response.getCode() == 200) {
                // Parse response
                Token token = this.mapper.readValue(response.getBodyText(), Token.class);
                // Notify listeners
                listeners.forEach(listener -> listener.onTokenChanged(token));
                // Return token
                return token;
            } else {
                log.warn("Operation to fetch a permanent token failed: { \"status_code\": {}, \"message\": {} }", response.getCode(), response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain permanent token from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse permanent token: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Obtains a temporary HMAC-signed URL token for the given resource from CTI Console.
     * @param permanentToken permanent token for the instance.
     * @param resource resource to request the access token to.
     * @return resource access token
     */
    @Override
    public Token getResourceToken(String permanentToken, String resource) {
        try {
            // Perform request
            SimpleHttpResponse response = this.client.getResourceToken(permanentToken, resource);
            if (response.getCode() == 200) {
                // Parse response
                return this.mapper.readValue(response.getBodyText(), Token.class);
            } else {
                log.warn("Operation to fetch a resource token failed: { \"status_code\": {}, \"message\": {}", response.getCode(), response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain resource token from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse resource token: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public void addListener(TokenListener listener) {
        this.listeners.add(listener);
    }
}
