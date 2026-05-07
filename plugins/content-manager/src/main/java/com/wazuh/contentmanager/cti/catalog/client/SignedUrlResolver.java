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

import com.wazuh.contentmanager.cti.console.service.TokenExchangeService;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * A URL resolver for registered environments. Exchanges the original resource URL for a temporary
 * HMAC-signed URL via the CTI Console token exchange endpoint.
 *
 * <p>If the token exchange fails (e.g., the instance was deregistered), the in-memory access token
 * is cleared and the original URL is returned as a fallback.
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
    public String resolve(String originalUrl) {
        String signedUrl = this.tokenExchangeService.getResourceToken(originalUrl, this.accessToken);
        if (signedUrl != null) {
            return signedUrl;
        }

        log.warn(
                "Token exchange failed for resource [{}]. Clearing access token and falling back to plain URL.",
                originalUrl);
        PluginSettings.getInstance().setAccessToken(null);
        return originalUrl;
    }
}
