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

import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;

/**
 * Service interface for exchanging an access token for a temporary, resource-specific HMAC-signed
 * URL via the CTI Console token exchange endpoint.
 */
public interface TokenExchangeService extends ClosableHttpClient {

    /**
     * Exchanges the given access token for a temporary HMAC-signed URL that grants access to the
     * specified resource.
     *
     * @param resource the full URL of the resource to which access is requested.
     * @param accessToken the OAuth 2.0 access token previously issued to the environment.
     * @return the HMAC-signed URL granting temporary access, or {@code null} if {@code resource} or
     *     {@code accessToken} is null or empty, or the CTI Console declined to sign the resource
     *     ({@code 400 invalid_target} or {@code invalid_request}); the caller then uses the plain
     *     URL.
     * @throws TokenRejectedException if the CTI Console rejects the access token: {@code 401}, or
     *     {@code 400} with the OAuth error {@code unauthorized_client}.
     * @throws CtiConsoleUnavailableException if the exchange fails for any other reason: network
     *     error, timeout, another error status, or an unparseable response.
     */
    String getResourceToken(String resource, String accessToken)
            throws TokenRejectedException, CtiConsoleUnavailableException;
}
