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
package com.wazuh.contentmanager.privileged;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;

import java.net.URI;
import java.security.AccessController;
import java.util.Map;

import com.wazuh.contentmanager.util.http.HttpClient;

/** Quick class to handle outgoing HTTP requests */
public class PrivilegedHttpAction {

    /** Empty constructor */
    public PrivilegedHttpAction() {}

    /**
     * Calls HttpClient with a GET request
     *
     * @param uri Destination URI
     * @param body The body of the request
     * @param queryParameters A map of the requests query parameters
     * @param headers The request's headers
     * @return
     */
    public static SimpleHttpResponse get(
            String uri, String body, Map<String, String> queryParameters, Header... headers) {
        return AccessController.doPrivileged(
                (java.security.PrivilegedAction<SimpleHttpResponse>)
                        () ->
                                HttpClient.getInstance()
                                        .get(URI.create(uri), body, queryParameters, headers));
    }
}
