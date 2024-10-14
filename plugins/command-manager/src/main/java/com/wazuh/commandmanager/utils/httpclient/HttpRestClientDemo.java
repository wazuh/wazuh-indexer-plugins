/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.utils.httpclient;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class HttpRestClientDemo {

    private static final Logger log = LogManager.getLogger(HttpRestClientDemo.class);

    public static void run(String endpoint, String body) {
        log.info("Executing POST request");
        AccessController.doPrivileged(
                (PrivilegedAction<SimpleHttpResponse>) () -> {
                    HttpRestClient httpClient = HttpRestClient.getInstance();
                    URI host;
                    try {
                        host = new URIBuilder(endpoint).build();
                    } catch (URISyntaxException e) {
                        throw new RuntimeException(e);
                    }
                    SimpleHttpResponse postResponse = httpClient.post(host, body);
                    log.info(postResponse.getBodyText());
                    return postResponse;
                }
        );
    }
}
