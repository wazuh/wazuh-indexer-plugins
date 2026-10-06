/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wazuh.contentmanager.cti.console.service.CtiConsoleUnavailableException;
import com.wazuh.contentmanager.cti.console.service.TokenExchangeService;
import com.wazuh.contentmanager.cti.console.service.TokenRejectedException;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * A URL resolver for registered environments. Exchanges the original resource URL for a temporary
 * HMAC-signed URL via the CTI Console token exchange endpoint.
 *
 * <p>If the CTI Console rejects the access token (e.g. the instance was deregistered), the
 * in-memory access token is cleared and the original URL is returned as a fallback. Any other
 * exchange failure keeps the token and fails the resolution, so the request fails like an
 * unreachable feed and is retried, instead of running unsigned or as an unregistered instance.
 */
public class SignedUrlResolver implements ResourceUrlResolver {
    private static final Logger log = LogManager.getLogger(SignedUrlResolver.class);

    private final TokenExchangeService tokenExchangeService;
    private final String accessToken;

    /**
     * Constructs a new SignedUrlResolver.
     *
     * @param tokenExchangeService the service used to exchange tokens for HMAC-signed URLs.
     * @param accessToken the permanent access token for this registered instance.
     */
    public SignedUrlResolver(TokenExchangeService tokenExchangeService, String accessToken) {
        this.tokenExchangeService = tokenExchangeService;
        this.accessToken = accessToken;
    }

    @Override
    public String resolve(String originalUrl) throws CtiConsoleUnavailableException {
        log.info("Resolving signed URL for resource [{}]", originalUrl);
        String signedUrl;
        try {
            signedUrl = this.tokenExchangeService.getResourceToken(originalUrl, this.accessToken);
        } catch (TokenRejectedException e) {
            log.warn(
                    "Token exchange rejected for resource [{}]. Clearing access token and falling back to plain URL.",
                    originalUrl);
            PluginSettings.getInstance().setAccessToken(null);
            return originalUrl;
        } catch (CtiConsoleUnavailableException e) {
            log.warn(
                    "Token exchange failed for resource [{}] ({}). The access token is kept.",
                    originalUrl,
                    e.getMessage());
            throw e;
        }
        if (signedUrl == null) {
            // Empty input, or the Console declined to sign this resource: not a token problem.
            log.warn("No signed URL for resource [{}]; using the plain URL.", originalUrl);
            return originalUrl;
        }
        log.info("Successfully obtained signed URL for resource [{}]", originalUrl);
        return signedUrl;
    }

    /**
     * Closes the underlying token-exchange service, releasing its HTTP client. Without this, the
     * client's I/O reactor selectors leak file descriptors on every catalog sync (issue #1763).
     */
    @Override
    public void close() {
        this.tokenExchangeService.close();
    }
}
