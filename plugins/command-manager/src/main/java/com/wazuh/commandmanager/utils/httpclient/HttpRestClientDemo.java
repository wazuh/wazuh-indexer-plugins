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
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.PrivilegedAction;

import com.wazuh.commandmanager.settings.PluginSettings;

import static com.wazuh.commandmanager.CommandManagerPlugin.COMMAND_MANAGER_BASE_URI;

/** Demo class to test the {@link HttpRestClient} class. */
public class HttpRestClientDemo {

    public static final String SECURITY_USER_AUTHENTICATE =
            COMMAND_MANAGER_BASE_URI + "/security/user/authenticate";
    public static final String ORDERS = "orders";
    private static final Logger log = LogManager.getLogger(HttpRestClientDemo.class);

    /**
     * Demo method to test the {@link HttpRestClient} class.
     *
     * @param endpoint POST's requests endpoint as a well-formed URI
     * @param body POST's request body as a JSON string.
     */
    public static void run(String endpoint, String body) {
        AccessController.doPrivileged(
                (PrivilegedAction<SimpleHttpResponse>)
                        () -> {
                            HttpRestClient httpClient = HttpRestClient.getInstance();
                            try {
                                URI host = new URIBuilder(endpoint).build();
                                httpClient.post(host, body, "randomId", (Header) null);
                            } catch (URISyntaxException e) {
                                log.error("Bad URI:{}", e.getMessage());
                            } catch (Exception e) {
                                log.error("Error reading response: {}", e.getMessage());
                            }
                            return null;
                        });
    }

    /**
     * Demo method to test the {@link HttpRestClient} class.
     *
     * @param body POST's request body as a JSON string.
     * @return
     */
    public static SimpleHttpResponse runWithResponse(String body, String docId) {
        log.info("Executing POST request");
        String mApiURI = PluginSettings.getInstance().getUri();
        SimpleHttpResponse response;
        response =
                AccessController.doPrivileged(
                        (PrivilegedAction<SimpleHttpResponse>)
                                () -> {
                                    AuthHttpRestClient httpClient = new AuthHttpRestClient();
                                    try {
                                        URI host = new URIBuilder(mApiURI).build();
                                        return httpClient.post(host, body, docId, (Header) null);
                                    } catch (URISyntaxException e) {
                                        log.error("Bad URI:{}", e.getMessage());
                                    } catch (Exception e) {
                                        log.error("Error sending data: {}", e.getMessage());
                                    }
                                    return null;
                                });
        return response;
    }
}
