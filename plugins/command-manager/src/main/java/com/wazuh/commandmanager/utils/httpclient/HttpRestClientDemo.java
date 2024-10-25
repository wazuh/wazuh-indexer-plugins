/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.utils.httpclient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;

import com.wazuh.commandmanager.auth.BasicAuthenticator;
import com.wazuh.commandmanager.settings.CommandManagerSettings;

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
                                SimpleHttpResponse response =
                                        httpClient.post(host, body, "randomId", null);
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

    /**
     * Demo method to test the {@link HttpRestClient} class.
     *
     * @param endpoint POST's requests endpoint as a well-formed URI
     * @param body POST's request body as a JSON string.
     * @return
     */
    public static SimpleHttpResponse runWithResponse(
            String endpoint, String body, String docId, CommandManagerSettings settings) {
        log.info("Executing POST request");
        SimpleHttpResponse response;
        response =
                AccessController.doPrivileged(
                        (PrivilegedAction<SimpleHttpResponse>)
                                () -> {
                                    HttpRestClient httpClient = HttpRestClient.getInstance();

                                    try {
                                        BasicAuthenticator auth = new BasicAuthenticator("m_API");
                                        auth.

                                                        // Login
                                                        URI
                                                loginUri =
                                                        new URIBuilder(endpoint)
                                                                .setPath(SECURITY_USER_AUTHENTICATE)
                                                                .build();
                                        log.info("Login in at [{}]", loginUri);
                                        String basicAuth =
                                                settings.getAuthUsername()
                                                        + ":"
                                                        + settings.getAuthPassword();
                                        String basicAuthHeader = "Basic " + basicAuth;
                                        SimpleHttpResponse loginResponse =
                                                httpClient.post(
                                                        loginUri, null, null, basicAuthHeader);
                                        log.info(
                                                "Received response to login request: {}",
                                                loginResponse.toString());
                                        log.info("Received body: {}", loginResponse.getBodyText());
                                        log.info(
                                                "Received headers: {}",
                                                Arrays.toString(loginResponse.getHeaders()));

                                        ObjectMapper mapper = new ObjectMapper();
                                        JsonNode root =
                                                mapper.readTree(loginResponse.getBodyText());
                                        String token = root.path("data").path("token").asText();
                                        System.out.println("JWT Token: " + token);

                                        if (token.isEmpty()) {
                                            throw new RuntimeException("Auth token is empty");
                                        }

                                        String jwtAuthHeader = "Bearer " + token;
                                        URI host = new URIBuilder(endpoint).setPath(ORDERS).build();
                                        return httpClient.post(host, body, docId, jwtAuthHeader);
                                    } catch (URISyntaxException e) {
                                        log.error("Bad URI:{}", e.getMessage());
                                    } catch (IOException e) {
                                        throw new RuntimeException(e);
                                    }
                                    return null;
                                });
        return response;
    }
}
