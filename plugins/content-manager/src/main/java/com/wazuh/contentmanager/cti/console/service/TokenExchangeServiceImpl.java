/*
 * Copyright (C) 2026, Wazuh Inc.
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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.utils.Constants;

/** Implementation of the {@link TokenExchangeService} interface. */
public class TokenExchangeServiceImpl extends AbstractService implements TokenExchangeService {
    private static final Logger log = LogManager.getLogger(TokenExchangeServiceImpl.class);

    /** Default constructor. */
    public TokenExchangeServiceImpl() {
        super();
    }

    /**
     * Exchanges the given access token for a temporary HMAC-signed URL that grants access to the
     * specified resource.
     *
     * @param resource the full URL of the resource to which access is requested.
     * @param accessToken the OAuth 2.0 access token previously issued to the environment.
     * @return the HMAC-signed URL granting temporary access, or {@code null} if the exchange fails.
     */
    @Override
    public String getResourceToken(String resource, String accessToken) {
        if (resource == null || resource.isEmpty()) {
            log.warn(Constants.W_LOG_RESOURCE_NULL_OR_EMPTY);
            return null;
        }
        if (accessToken == null || accessToken.isEmpty()) {
            log.warn(Constants.W_LOG_ACCESS_TOKEN_NULL_OR_EMPTY);
            return null;
        }

        try {
            Token permanentToken = new Token(accessToken, "Bearer");

            SimpleHttpResponse response = this.client.getResourceToken(permanentToken, resource);

            if (response.getCode() == 200) {
                Token resourceToken = this.mapper.readValue(response.getBodyText(), Token.class);
                return resourceToken.getAccessToken();
            } else {
                log.warn(Constants.W_LOG_CTI_RESOURCE_TOKEN_FAILED);
                log.debug(
                        Constants.D_LOG_CTI_RESOURCE_TOKEN_RESPONSE_DETAIL,
                        response.getCode(),
                        response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error(Constants.E_LOG_CTI_RESOURCE_TOKEN_FAILED);
            log.debug(Constants.D_LOG_CTI_RESOURCE_TOKEN_DETAIL, e.getMessage());
        } catch (IOException e) {
            log.error(Constants.E_LOG_CTI_RESOURCE_TOKEN_PARSE_FAILED);
            log.debug(Constants.D_LOG_CTI_RESOURCE_TOKEN_DETAIL, e.getMessage());
        }
        return null;
    }
}
