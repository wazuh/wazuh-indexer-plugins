/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.utils.httpclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

import com.wazuh.commandmanager.auth.AuthCredentials;
import com.wazuh.commandmanager.auth.HTTPAuthenticator;
import com.wazuh.commandmanager.settings.CommandManagerSettings;

public class AuthHttpRestClient extends HttpRestClient implements HTTPAuthenticator {

    public static final String SECURITY_USER_AUTHENTICATE = "/security/user/authenticate";
    private static final Logger log = LogManager.getLogger(AuthHttpRestClient.class);

    private final AuthCredentials credentials;

    /** Default constructor */
    public AuthHttpRestClient() {
        super();

        this.credentials =
                new AuthCredentials(
                        CommandManagerSettings.getInstance().getAuthUsername(),
                        CommandManagerSettings.getInstance().getAuthPassword());
    }

    /**
     * Sends a POST request.
     *
     * @param receiverURI Well-formed URI
     * @param payload data to send
     * @param payloadId payload ID
     * @param headers auth value (Basic "user:password", "Bearer token")
     * @return SimpleHttpResponse response
     */
    @Override
    public SimpleHttpResponse post(
            URI receiverURI, String payload, String payloadId, Header... headers) {
        try {
            return this.post(receiverURI, payload, payloadId, 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Sends a POST request.
     *
     * @param receiverURI Well-formed URI
     * @param payload data to send
     * @param payloadId payload ID
     * @param retries retries counter
     * @return SimpleHttpResponse response
     */
    public SimpleHttpResponse post(
            URI receiverURI, String payload, String payloadId, Integer retries) throws Exception {

        // Recursive calls exit condition.
        if (retries == MAX_RETRIES) {
            String message =
                    String.format(
                            Locale.ROOT,
                            "Max retries [%d/%d] reached for POST request with id [%s]",
                            retries,
                            MAX_RETRIES,
                            payloadId);
            throw new Exception(message);
        }

        // Authenticate if required.
        if (!this.credentials.isTokenSet()) {
            this.authenticate();
        }

        // Perform POST request.
        SimpleHttpResponse response =
                super.post(receiverURI, payload, payloadId, this.credentials.getAuthAsHeaders());

        // Handle unauthorized responses.
        if (response.getCode() == RestStatus.UNAUTHORIZED.getStatus()) {
            // Invalidate current token.
            this.credentials.setToken(null);
            log.info("Token invalidated");
            // Retry request.
            this.post(receiverURI, payload, payloadId, ++retries);
        } else if (response.getCode() == RestStatus.OK.getStatus()) {
            return response;
        }

        return null;
    }

    /**
     * @return
     */
    @Override
    public AuthCredentials getCredentials() {
        return this.credentials;
    }

    @Override
    public void authenticate() {
        // Replace with PluginSettings.getInstance().getAPI();
        String mApiURI = CommandManagerSettings.getInstance().getUri();
        try {
            URI loginUri = new URIBuilder(mApiURI).appendPath(SECURITY_USER_AUTHENTICATE).build();

            log.info("Attempting authentication at [{}]", loginUri);
            SimpleHttpResponse loginResponse =
                    super.post(loginUri, null, null, this.credentials.getAuthAsHeaders());

            if (loginResponse.getCode() == RestStatus.OK.getStatus()) {
                // Parse JSON response to extract and save the JWT token.
                ObjectMapper mapper = new ObjectMapper();
                JsonNode root = mapper.readTree(loginResponse.getBodyText());
                String token = root.path("data").path("token").asText();
                this.credentials.setToken(token);
                log.info("Authentication successful");
            } else {
                log.error("Authentication failed due to: {}", loginResponse.getBody());
            }
        } catch (URISyntaxException e) {
            log.error("Invalid URI. Is the IP to the Wazuh Server set? - {}", e.getMessage());
        } catch (JsonMappingException e) {
            log.error("Mapping error on JSON response: {}", e.getMessage());
        } catch (JsonProcessingException e) {
            log.error("Processing error on JSON response: {}", e.getMessage());
        }
    }
}
