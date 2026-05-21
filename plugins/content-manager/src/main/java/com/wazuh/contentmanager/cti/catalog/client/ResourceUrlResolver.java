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

/**
 * Resolves CTI resource URLs before HTTP requests are made. For non-registered environments, the
 * URL is returned as-is. For registered environments, the URL is exchanged for a temporary
 * HMAC-signed URL via the CTI Console token exchange endpoint.
 */
public interface ResourceUrlResolver {

    /**
     * Resolves the given resource URL into the URL that should actually be used for the HTTP request.
     *
     * @param originalUrl the original CTI resource URL.
     * @return the resolved URL to use for the request.
     */
    String resolve(String originalUrl);
}
