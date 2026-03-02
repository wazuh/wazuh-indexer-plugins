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

import com.fasterxml.jackson.databind.ObjectMapper;

import com.wazuh.contentmanager.cti.console.client.ApiClient;

/** Abstract service class, for generalization. */
public abstract class AbstractService {

    ApiClient client;
    final ObjectMapper mapper;

    /** Default constructor */
    public AbstractService() {
        this.client = new ApiClient();
        this.mapper = new ObjectMapper();
    }

    /**
     * Use for testing only.
     *
     * @param c mocked client.
     */
    public void setClient(ApiClient c) {
        this.close();
        this.client = c;
    }

    /** Closes the underlying HTTP client. Should be called when the service is no longer needed. */
    public void close() {
        if (this.client != null) {
            this.client.close();
        }
    }
}
