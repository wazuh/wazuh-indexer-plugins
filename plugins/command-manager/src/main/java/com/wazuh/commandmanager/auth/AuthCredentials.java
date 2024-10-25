/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.auth;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;

import reactor.util.annotation.Nullable;

public class AuthCredentials {
    private String username;
    private String password;
    private String token;

    public AuthCredentials(String username, String password) {
        this.username = username;
        this.password = password;
        this.token = null;
    }

    public AuthCredentials() {
        //        CommandManagerSettings.M_API_PASSWORD.get()
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

    public void setToken(@Nullable String token) {
        this.token = token;
    }
}
