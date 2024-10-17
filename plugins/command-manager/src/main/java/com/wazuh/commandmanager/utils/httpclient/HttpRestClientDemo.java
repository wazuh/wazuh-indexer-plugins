/*
 * Copyright OpenSearch Contributors
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

/** Demo class to test the {@link HttpRestClient} class. */
public class HttpRestClientDemo {

    private static final Logger log = LogManager.getLogger(HttpRestClientDemo.class);

    /**
     * Demo method to test the {@link HttpRestClient} class.
     *
     * @param endpoint POST's requests endpoint as a well-formed URI
     * @param body POST's request body as a JSON string.
     */
    public static void run(String endpoint, String body) {
        log.info("Executing POST request");
        AccessController.doPrivileged(
                (PrivilegedAction<SimpleHttpResponse>)
                        () -> {
                            HttpRestClient httpClient = HttpRestClient.getInstance();
                            try {
                                URI host = new URIBuilder(endpoint).build();
                                SimpleHttpResponse response =
                                        httpClient.post(host, body, "randomId");
                                log.info(
                                        "Received response to POST request with code {}",
                                        response.getCode());
                                log.info("Raw response:\n{}", response.getBodyText());
                            } catch (URISyntaxException e) {
                                log.error("Bad URI:{}", e.getMessage());
                            } catch (Exception e) {
                                log.error("Error reading response: {}", e.getMessage());
                            }
                            return null;
                        });
    }
}
