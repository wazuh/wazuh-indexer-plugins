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
package com.wazuh.commandmanager.auth;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;

import reactor.util.annotation.Nullable;

public class AuthCredentials {
    /** Wazuh API username for basic authentication */
    private final String username;

    /** Wazuh API password for basic authentication */
    private final String password;

    /** Token for the Wazuh API as obtained from /security/user/authenticate */
    private String token;

    public AuthCredentials(String username, String password) {
        this.username = username;
        this.password = password;
        this.token = null;
    }

    private Header getTokenHeader() {
        return new BasicHeader(HttpHeaders.AUTHORIZATION, "Bearer " + this.token);
    }

    private Header getBasicAuthHeader() {
        return new BasicHeader(
                HttpHeaders.AUTHORIZATION, "Basic " + this.username + ":" + this.password);
    }

    public Header getAuthAsHeaders() {
        if (this.token != null) {
            return this.getTokenHeader();
        }
        return getBasicAuthHeader();
    }

    /**
     * @param token
     */
    public void setToken(@Nullable String token) {
        this.token = token;
    }

    /**
     * Checks if the token is different from null.
     *
     * @return
     */
    public boolean isTokenSet() {
        return this.token != null;
    }
}
