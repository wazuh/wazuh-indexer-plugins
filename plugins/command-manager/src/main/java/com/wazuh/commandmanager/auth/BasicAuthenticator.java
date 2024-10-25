/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

import com.wazuh.commandmanager.utils.httpclient.HttpRestClient;

public class BasicAuthenticator implements HTTPAuthenticator {

    public static final String SECURITY_USER_AUTHENTICATE = "/security/user/authenticate";
    private static final Logger log = LogManager.getLogger(BasicAuthenticator.class);

    private final String type;
    private AuthCredentials credentials;

    public BasicAuthenticator(String type) {
        this.type = type;
    }

    /**
     * @return
     */
    @Override
    public String getType() {
        return this.type;
    }

    /**
     * @return
     */
    @Override
    public AuthCredentials getCredentials() {
        return this.credentials;
    }

    /**
     * @param credentials
     */
    @Override
    public void authenticate(AuthCredentials credentials) {
        // Replace with PluginSettings.getInstance().getAPI();
        String mApiUri = "https://127.0.0.1/_plugins/_command-manager";
        HttpRestClient httpClient = HttpRestClient.getInstance();

        try {
            URI loginUri = new URIBuilder(mApiUri).setPath(SECURITY_USER_AUTHENTICATE).build();

            log.info("Attempting authentication at [{}]", loginUri);
            SimpleHttpResponse loginResponse =
                    httpClient.post(loginUri, null, null, credentials.getAuthAsHeaders());
            log.info("Received response to authentication request: {}", loginResponse.toString());
            log.info("Received body: {}", loginResponse.getBodyText());
            log.info("Received headers: {}", Arrays.toString(loginResponse.getHeaders()));

            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(loginResponse.getBodyText());
            String token = root.path("data").path("token").asText();
            System.out.println("JWT Token: " + token);
            log.info("Authentication successful");
            credentials.setToken(token);
        } catch (URISyntaxException e) {
            log.error("Invalid URI. Is the IP to the Wazuh Server set? - {}", e.getMessage());
        } catch (JsonMappingException e) {
            log.error("Mapping error on JSON response: {}", e.getMessage());
        } catch (JsonProcessingException e) {
            log.error("Processing error on JSON response: {}", e.getMessage());
        }
    }
}
