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

import com.fasterxml.jackson.databind.JsonNode;

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

    /** OAuth error for an invalid, expired or revoked token. */
    static final String ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client";

    /** OAuth error for a resource the CTI Console does not sign for this environment. */
    static final String ERROR_INVALID_TARGET = "invalid_target";

    /** OAuth error for a malformed exchange request, such as a missing resource. */
    static final String ERROR_INVALID_REQUEST = "invalid_request";

    /** Default constructor. */
    public TokenExchangeServiceImpl() {
        super();
    }

    /**
     * Exchanges the given access token for a temporary HMAC-signed URL that grants access to the
     * specified resource. A {@code 401}, or a {@code 400} with the OAuth error {@code
     * unauthorized_client}, is a rejected token. A {@code 400} with {@code invalid_target} or {@code
     * invalid_request} means the Console does not sign this resource. Any other failure leaves the
     * token's validity unknown.
     *
     * @param resource the full URL of the resource to which access is requested.
     * @param accessToken the OAuth 2.0 access token previously issued to the environment.
     * @return the HMAC-signed URL granting temporary access, or {@code null} if {@code resource} or
     *     {@code accessToken} is null or empty, or the Console declined to sign the resource.
     * @throws TokenRejectedException if the CTI Console rejects the access token.
     * @throws CtiConsoleUnavailableException if the exchange fails for any other reason.
     */
    @Override
    public String getResourceToken(String resource, String accessToken)
            throws TokenRejectedException, CtiConsoleUnavailableException {
        if (resource == null || resource.isEmpty()) {
            log.warn(Constants.W_LOG_RESOURCE_NULL_OR_EMPTY);
            return null;
        }
        if (accessToken == null || accessToken.isEmpty()) {
            log.warn(Constants.W_LOG_ACCESS_TOKEN_NULL_OR_EMPTY);
            return null;
        }

        SimpleHttpResponse response;
        try {
            response = this.client.getResourceToken(new Token(accessToken, "Bearer"), resource);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw this.exchangeFailed(e);
        } catch (ExecutionException | TimeoutException e) {
            throw this.exchangeFailed(e);
        }

        if (response.getCode() != 200) {
            log.warn(Constants.W_LOG_CTI_RESOURCE_TOKEN_FAILED);
            log.debug(
                    Constants.D_LOG_CTI_RESOURCE_TOKEN_RESPONSE_DETAIL,
                    response.getCode(),
                    response.getBodyText());
            String error = response.getCode() == 400 ? this.oauthError(response) : null;
            // The token exchange reports a revoked or expired token as 400 unauthorized_client
            // (RFC 8693 / RFC 6749 error codes), not as 401. Accept both.
            if (response.getCode() == 401 || ERROR_UNAUTHORIZED_CLIENT.equals(error)) {
                throw new TokenRejectedException(
                        "The CTI Console rejected the access token (status "
                                + response.getCode()
                                + (error != null ? ", " + error : "")
                                + ").");
            }
            // The request was understood but this resource is not signed for the environment. That
            // says nothing about the token: let the caller use the plain URL.
            if (ERROR_INVALID_TARGET.equals(error) || ERROR_INVALID_REQUEST.equals(error)) {
                log.warn(Constants.W_LOG_CTI_RESOURCE_TOKEN_DECLINED, resource, error);
                return null;
            }
            throw new CtiConsoleUnavailableException(
                    "The CTI Console answered status "
                            + response.getCode()
                            + (error != null ? " (" + error + ")" : "")
                            + " to the token exchange.");
        }
        try {
            Token resourceToken = this.mapper.readValue(response.getBodyText(), Token.class);
            if (resourceToken.getAccessToken() == null || resourceToken.getAccessToken().isEmpty()) {
                throw new IOException("no access_token in the response");
            }
            return resourceToken.getAccessToken();
        } catch (IOException e) {
            log.error(Constants.E_LOG_CTI_RESOURCE_TOKEN_PARSE_FAILED);
            log.debug(Constants.D_LOG_CTI_RESOURCE_TOKEN_DETAIL, e.getMessage());
            throw new CtiConsoleUnavailableException("Failed to parse the token exchange response.", e);
        }
    }

    /**
     * Reads the OAuth {@code error} code of a token-exchange error response.
     *
     * @return the error code, or {@code null} if the body is not a JSON object with a textual {@code
     *     error} field.
     */
    private String oauthError(SimpleHttpResponse response) {
        try {
            JsonNode error = this.mapper.readTree(response.getBodyText()).get("error");
            return error != null && error.isTextual() ? error.asText() : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private CtiConsoleUnavailableException exchangeFailed(Exception e) {
        log.error(Constants.E_LOG_CTI_RESOURCE_TOKEN_FAILED);
        log.debug(Constants.D_LOG_CTI_RESOURCE_TOKEN_DETAIL, e.getMessage());
        return new CtiConsoleUnavailableException(
                "The token exchange request to the CTI Console failed.", e);
    }
}
