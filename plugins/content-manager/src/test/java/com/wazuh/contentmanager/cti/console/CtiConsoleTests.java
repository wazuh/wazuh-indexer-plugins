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
package com.wazuh.contentmanager.cti.console;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Subscription;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.AuthService;
import com.wazuh.contentmanager.cti.console.service.AuthServiceImpl;
import com.wazuh.contentmanager.cti.console.service.PlansService;
import com.wazuh.contentmanager.cti.console.service.PlansServiceImpl;
import org.mockito.Mock;

import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link CtiConsole} class. This test suite validates the core console
 * functionality for managing CTI service authentication and token lifecycle.
 *
 * <p>Tests verify the observer pattern implementation for token updates, proper integration with
 * authentication and plans services, and correct token propagation to registered listeners. Mock
 * HTTP clients simulate CTI API interactions without requiring network connectivity.
 */
public class CtiConsoleTests extends OpenSearchTestCase {
    private CtiConsole console;
    private AuthService authService;
    private PlansService plansService;
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
        this.plansService = new PlansServiceImpl();
        this.authService.setClient(this.mockClient);
        this.plansService.setClient(this.mockClient);

        this.console = new CtiConsole();
        this.console.setAuthService(this.authService);
        this.console.setPlansService(this.plansService);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();

        this.authService.close();
        this.plansService.close();
    }

    /**
     * When the auth service is successful obtaining a permanent token from the CTI Console, it must
     * invoke the onTokenChange() method for all its listeners (CtiConsole). As a result, the token
     * from the CtiConsole instances are updated / initialized.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testOnTokenChanged()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Mock client response upon request
        String response =
                "{\"access_token\": \"AYjcyMzY3ZDhiNmJkNTY\", \"refresh_token\": \"RjY2NjM5NzA2OWJjuE7c\", \"token_type\": \"Bearer\", \"expires_in\": 3600}";
        when(this.mockClient.getToken(anyString(), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Subscription subscription = new Subscription("anyClientID", "anyDeviceCode", 3600, 5);
        Token tokenA = this.authService.getToken(subscription);

        // Ensure onTokenChanged is invoked, and the token in the CtiConsole instance is updated.
        Token tokenB = this.console.getToken();
        Assert.assertEquals(tokenA, tokenB);
    }

    /**
     * Tests the token retrieval mechanism with wait/notify synchronization. The test verifies that
     * the calling thread properly waits for the token to be obtained through the polling mechanism
     * and is notified when the token becomes available.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetToken() throws ExecutionException, InterruptedException, TimeoutException {
        String responsePending = "{\"error\": \"authorization_pending\"}";
        String response =
                "{\"access_token\": \"AYjcyMzY3ZDhiNmJkNTY\", \"refresh_token\": \"RjY2NjM5NzA2OWJjuE7c\", \"token_type\": \"Bearer\", \"expires_in\": 3600}";

        // Mock responses: 3 pending, success on 4th.
        SimpleHttpResponse httpResponsePending =
                SimpleHttpResponse.create(
                        400, responsePending.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON);
        SimpleHttpResponse httpResponse =
                SimpleHttpResponse.create(
                        200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON);
        when(this.mockClient.getToken(anyString(), anyString()))
                .thenReturn(httpResponsePending, httpResponsePending, httpResponsePending, httpResponse);

        // Start polling
        Subscription subscription = new Subscription("anyClientID", "anyDeviceCode", 3600, 5);
        this.console.onPostSubscriptionRequest(subscription);

        // Wait for the token with a timeout
        Token token = this.console.waitForToken();

        // Verify the token was obtained
        Assert.assertTrue(this.console.isTokenTaskCompleted());
        Assert.assertNotNull(token);
        Assert.assertEquals("AYjcyMzY3ZDhiNmJkNTY", token.getAccessToken());
    }
}
