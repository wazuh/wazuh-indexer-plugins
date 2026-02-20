/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.console.service;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Subscription;
import com.wazuh.contentmanager.cti.console.model.Token;
import org.mockito.Mock;

import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link AuthService} interface and its implementation. This test suite
 * validates OAuth 2.0 device authorization flow with the CTI service including token retrieval,
 * refresh, and error handling.
 *
 * <p>Tests cover successful token acquisition, handling of malformed responses, network failures,
 * and proper cleanup of HTTP client resources. Mock HTTP clients simulate various CTI API response
 * scenarios without requiring actual network calls.
 */
public class AuthServiceTests extends OpenSearchTestCase {
    private AuthService authService;
    @Mock private ApiClient mockClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        // Mock CTI Console API Client
        this.mockClient = mock(ApiClient.class);

        // Create service and replace its client with the mock
        // Note: This creates a real ApiClient internally first, which needs to be closed
        this.authService = new AuthServiceImpl();
        this.authService.setClient(this.mockClient);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        // Close the service to properly shut down the HTTP client
        if (this.authService != null) {
            this.authService.close();
        }
    }

    /**
     * On success: - token must not be null - token.access_token must be a valid string (not null, not
     * empty)
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetTokenSuccess()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Mock client response upon request
        String response =
                "{\"access_token\": \"AYjcyMzY3ZDhiNmJkNTY\", \"refresh_token\": \"RjY2NjM5NzA2OWJjuE7c\", \"token_type\": \"Bearer\", \"expires_in\": 3600}";
        when(this.mockClient.getToken(anyString(), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Subscription subscription = new Subscription("anyClientID", "anyDeviceCode", 3600, 5);
        Token token = this.authService.getToken(subscription);

        // Token must not be null
        Assert.assertNotNull(token);

        // access_token must be a valid string (not null, not empty)
        Assert.assertNotNull(token.getAccessToken());
        Assert.assertFalse(token.getAccessToken().isEmpty());
    }

    /**
     * Possible failures - CTI replies with an error - CTI unreachable in these cases, the method is
     * expected to return null.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetTokenFailure()
            throws ExecutionException, InterruptedException, TimeoutException {
        Token token;
        String response =
                "{\"error\": \"invalid_request\", \"error_description\": \"Missing or invalid parameter: client_id\"}";
        Subscription subscription = new Subscription("anyClientID", "anyDeviceCode", 3600, 5);

        // When CTI replies with an error code, token must be null. No exception raised
        when(this.mockClient.getToken(anyString(), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                400, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));
        token = this.authService.getToken(subscription);
        Assert.assertNull(token);

        // When CTI does not reply, token must be null and exceptions are raised.
        when(this.mockClient.getToken(anyString(), anyString())).thenThrow(ExecutionException.class);
        token = this.authService.getToken(subscription);
        Assert.assertNull(token);
    }

    /**
     * On success: - token must not be null - token.access_token must be a valid string (not null, not
     * empty)
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetResourceTokenSuccess()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Mock client response upon request
        String response =
                "{\"access_token\": \"https://localhost:8443/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF\", \"issued_token_type\": \"urn:wazuh:params:oauth:token-type:signed_url\", \"expires_in\": 300}";
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Token token = this.authService.getResourceToken(new Token("anyToken", "Bearer"), "anyResource");

        // Token must not be null
        Assert.assertNotNull(token);

        // access_token must be a valid string (not null, not empty)
        Assert.assertNotNull(token.getAccessToken());
        Assert.assertFalse(token.getAccessToken().isEmpty());
    }

    /**
     * Possible failures - CTI replies with an error - CTI unreachable in these cases, the method is
     * expected to return null.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetResourceTokenFailure()
            throws ExecutionException, InterruptedException, TimeoutException {
        Token token;
        String response =
                "{\"error\": \"invalid_target\", \"error_description\": \"The resource parameter refers to an invalid endpoint\"}";

        // When CTI replies with an error code, token must be null. No exception raised
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                400, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));
        token = this.authService.getResourceToken(new Token("anyToken", "Bearer"), "anyResource");
        Assert.assertNull(token);

        // When CTI does not reply, token must be null and exceptions are raised.
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenThrow(ExecutionException.class);
        token = this.authService.getResourceToken(new Token("anyToken", "Bearer"), "anyResource");
        Assert.assertNull(token);
    }
}
