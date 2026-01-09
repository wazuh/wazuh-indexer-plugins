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

import com.wazuh.contentmanager.cti.console.TokenListener;
import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;
import com.wazuh.contentmanager.cti.console.model.Subscription;
import com.wazuh.contentmanager.cti.console.model.Token;

/**
 * Service interface for handling authentication with the CTI Console. Manages the retrieval of
 * permanent tokens and resource-specific tokens.
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
