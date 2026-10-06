/*
 * Copyright (C) 2026, Wazuh Inc.
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
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Mock;

import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link TokenExchangeService} interface and its implementation. This test suite
 * validates the token exchange flow, where an access token is exchanged for a temporary HMAC-signed
 * URL granting access to a specific CTI resource.
 */
public class TokenExchangeServiceTests extends OpenSearchTestCase {
    private TokenExchangeService tokenExchangeService;
    @Mock private ApiClient mockClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
            // Already initialized
        }

        this.mockClient = mock(ApiClient.class);

        this.tokenExchangeService = new TokenExchangeServiceImpl();
        this.tokenExchangeService.setClient(this.mockClient);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.tokenExchangeService != null) {
            this.tokenExchangeService.close();
        }
    }

    /**
     * On success: - signed URL must not be null - signed URL must not be empty
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetResourceTokenSuccess() throws Exception {
        String response =
                "{\"access_token\": \"https://localhost:8443/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF\", \"issued_token_type\": \"urn:wazuh:params:oauth:token-type:signed_url\", \"expires_in\": 300}";
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        String signedUrl = this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken");

        Assert.assertNotNull(signedUrl);
        Assert.assertFalse(signedUrl.isEmpty());
    }

    /**
     * Failures that say nothing about the token (a 400 without a known OAuth error, another error
     * status, no answer, a timeout, an unusable body) raise {@link CtiConsoleUnavailableException},
     * so the caller keeps the token.
     *
     * @throws Exception ignored
     */
    public void testGetResourceTokenFailure() throws Exception {
        String[][] cases = {
            {"400", "{\"error\": \"server_error\"}"},
            {"400", "not json"},
            {"403", "{\"error\": \"access_denied\"}"},
            {"429", "{}"},
            {"500", "{}"},
            {"503", "{\"error\": \"unauthorized_client\"}"}
        };
        for (String[] c : cases) {
            this.stubExchange(Integer.parseInt(c[0]), c[1]);
            CtiConsoleUnavailableException e =
                    expectThrows(
                            CtiConsoleUnavailableException.class,
                            () -> this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken"));
            Assert.assertTrue(e.getMessage(), e.getMessage().contains(c[0]));
        }

        for (String body : new String[] {"not json", "{}"}) {
            this.stubExchange(200, body);
            expectThrows(
                    CtiConsoleUnavailableException.class,
                    () -> this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken"));
        }

        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenThrow(new ExecutionException(new java.net.ConnectException("Connection refused")))
                .thenThrow(new TimeoutException("5 SECONDS"));
        expectThrows(
                CtiConsoleUnavailableException.class,
                () -> this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken"));
        CtiConsoleUnavailableException timeout =
                expectThrows(
                        CtiConsoleUnavailableException.class,
                        () -> this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken"));
        Assert.assertTrue(timeout.getCause() instanceof TimeoutException);
    }

    /**
     * The exchange reports an invalid, expired or revoked token as 400 {@code unauthorized_client}; a
     * 401 is accepted too. Both are a rejected token.
     *
     * @throws Exception ignored
     */
    public void testGetResourceTokenUnauthorized() throws Exception {
        String response =
                "{\"error\": \"unauthorized_client\", \"error_description\": \"The provided token is invalid or expired\"}";
        for (int status : new int[] {400, 401}) {
            this.stubExchange(status, response);
            expectThrows(
                    TokenRejectedException.class,
                    () -> this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken"));
        }
    }

    /**
     * A 400 {@code invalid_target} or {@code invalid_request} means the Console does not sign this
     * resource. That says nothing about the token: null, so the caller uses the plain URL.
     *
     * @throws Exception ignored
     */
    public void testGetResourceTokenDeclined() throws Exception {
        for (String error : new String[] {"invalid_target", "invalid_request"}) {
            this.stubExchange(400, "{\"error\": \"" + error + "\", \"error_description\": \"declined\"}");
            Assert.assertNull(
                    this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken"));
        }
    }

    private void stubExchange(int status, String body) throws Exception {
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                status, body.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));
    }

    /**
     * A null or empty resource or token is not sent and returns null.
     *
     * @throws Exception ignored
     */
    public void testGetResourceTokenInvalidArguments() throws Exception {
        Assert.assertNull(this.tokenExchangeService.getResourceToken(null, "anyAccessToken"));
        Assert.assertNull(this.tokenExchangeService.getResourceToken("anyResource", ""));
        verify(this.mockClient, never()).getResourceToken(any(Token.class), anyString());
    }
}
