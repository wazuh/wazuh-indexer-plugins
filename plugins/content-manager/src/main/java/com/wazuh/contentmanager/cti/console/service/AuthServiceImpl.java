/*
 * Copyright (C) 2024, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager.cti.console.service;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.TokenListener;
import com.wazuh.contentmanager.cti.console.model.Subscription;
import com.wazuh.contentmanager.cti.console.model.Token;

/** Implementation of the AuthService interface. */
public class AuthServiceImpl extends AbstractService implements AuthService {
    private static final Logger log = LogManager.getLogger(AuthServiceImpl.class);
    private final List<TokenListener> listeners;

    /** Default constructor */
    public AuthServiceImpl() {
        super();
        this.listeners = new CopyOnWriteArrayList<>();
    }

    /**
     * Obtains a permanent token for the instance from CTI Console.
     *
     * @param subscription registration details of the instance.
     * @return access token.
     */
    @Override
    public Token getToken(Subscription subscription) {
        try {
            // Perform request
            SimpleHttpResponse response =
                    this.client.getToken(subscription.getClientId(), subscription.getDeviceCode());

            if (response.getCode() == 200) {
                // Parse response
                Token token = this.mapper.readValue(response.getBodyText(), Token.class);
                // Notify listeners
                this.listeners.forEach(listener -> listener.onTokenChanged(token));
                // Return token
                return token;
            } else {
                log.warn(
                        "Operation to fetch a permanent token failed: { \"status_code\": {}, \"message\": {} }",
                        response.getCode(),
                        response.getBodyText());
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
     *
     * @param permanentToken permanent token for the instance.
     * @param resource resource to request the access token to.
     * @return resource access token
     */
    @Override
    public Token getResourceToken(Token permanentToken, String resource) {
        try {
            // Perform request
            SimpleHttpResponse response = this.client.getResourceToken(permanentToken, resource);
            if (response.getCode() == 200) {
                // Parse response
                return this.mapper.readValue(response.getBodyText(), Token.class);
            } else {
                log.warn(
                        "Operation to fetch a resource token failed: { \"status_code\": {}, \"message\": {}",
                        response.getCode(),
                        response.getBodyText());
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
