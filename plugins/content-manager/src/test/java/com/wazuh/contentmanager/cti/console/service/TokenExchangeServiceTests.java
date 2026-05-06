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
 * validates the token exchange flow, where an access token is exchanged for a temporary
 * HMAC-signed URL granting access to a specific CTI resource.
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
    public void testGetResourceTokenSuccess()
            throws ExecutionException, InterruptedException, TimeoutException {
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
     * Possible failures - CTI replies with an error - CTI unreachable In these cases, the method is
     * expected to return null.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetResourceTokenFailure()
            throws ExecutionException, InterruptedException, TimeoutException {
        String signedUrl;
        String response =
                "{\"error\": \"invalid_target\", \"error_description\": \"The resource parameter refers to an invalid endpoint\"}";

        // When CTI replies with an error code, result must be null
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                400, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));
        signedUrl = this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken");
        Assert.assertNull(signedUrl);

        // When CTI does not reply, result must be null
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenThrow(ExecutionException.class);
        signedUrl = this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken");
        Assert.assertNull(signedUrl);
    }

    /**
     * When the server returns 401 (unauthorized), the method must return null.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetResourceTokenUnauthorized()
            throws ExecutionException, InterruptedException, TimeoutException {
        String response =
                "{\"error\": \"unauthorized_client\", \"error_description\": \"The provided token is invalid or expired\"}";
        when(this.mockClient.getResourceToken(any(Token.class), anyString()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                401, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        String signedUrl = this.tokenExchangeService.getResourceToken("anyResource", "anyAccessToken");
        Assert.assertNull(signedUrl);
    }
}
