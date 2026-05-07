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
 * A no-op URL resolver that returns the original URL unchanged. Used for non-registered
 * environments where CTI content is accessed via regular HTTP requests without authentication.
 */
public class IdentityUrlResolver implements ResourceUrlResolver {

    /** Default constructor. */
    public IdentityUrlResolver() {}

    @Override
    public String resolve(String originalUrl) {
        return originalUrl;
    }
}
