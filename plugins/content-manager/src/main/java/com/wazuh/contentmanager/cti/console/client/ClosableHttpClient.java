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
package com.wazuh.contentmanager.cti.console.client;

/** Represents a closable HTTP client wrapper used within the CTI console context. */
public interface ClosableHttpClient {

    /**
     * Sets the underlying API client instance to be used by this implementation.
     *
     * @param c the {@link ApiClient} instance to assign to this closable client.
     */
    void setClient(ApiClient c);

    /** Closes this client and releases any system resources associated with it. */
    void close();
}
