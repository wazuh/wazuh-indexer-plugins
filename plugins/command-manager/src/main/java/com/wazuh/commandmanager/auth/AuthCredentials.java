/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
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
