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
package com.wazuh.contentmanager.cti.catalog.client;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.cti.console.service.TokenExchangeService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.settings.PluginSettingsTests;

import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link SignedUrlResolver}. Verifies correct HMAC-signed URL resolution and
 * fallback behavior when token exchange fails.
 */
public class SignedUrlResolverTests extends OpenSearchTestCase {

    private static final String ORIGINAL_URL =
            "https://cti.wazuh.com/catalog/contexts/wazuh/consumers/ruleset";
    private static final String SIGNED_URL =
            "https://cti.wazuh.com/catalog/contexts/wazuh/consumers/ruleset?verify=1761383411-kJ9b8w";
    private static final String ACCESS_TOKEN = "test-permanent-token";

    private TokenExchangeService mockTokenExchangeService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettingsTests.clearInstance();
        PluginSettings.getInstance(Settings.EMPTY);
        PluginSettings.getInstance().setAccessToken(ACCESS_TOKEN);

        this.mockTokenExchangeService = mock(TokenExchangeService.class);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettingsTests.clearInstance();
        super.tearDown();
    }

    /** Tests that resolve returns the signed URL when token exchange succeeds. */
    public void testResolveReturnsSignedUrl() {
        when(this.mockTokenExchangeService.getResourceToken(ORIGINAL_URL, ACCESS_TOKEN))
                .thenReturn(SIGNED_URL);

        SignedUrlResolver resolver = new SignedUrlResolver(this.mockTokenExchangeService, ACCESS_TOKEN);
        String result = resolver.resolve(ORIGINAL_URL);

        Assert.assertEquals(SIGNED_URL, result);
        verify(this.mockTokenExchangeService).getResourceToken(ORIGINAL_URL, ACCESS_TOKEN);
    }

    /** Tests that resolve falls back to the original URL when token exchange returns null. */
    public void testResolveFallsBackToOriginalUrlOnFailure() {
        when(this.mockTokenExchangeService.getResourceToken(ORIGINAL_URL, ACCESS_TOKEN))
                .thenReturn(null);

        SignedUrlResolver resolver = new SignedUrlResolver(this.mockTokenExchangeService, ACCESS_TOKEN);
        String result = resolver.resolve(ORIGINAL_URL);

        Assert.assertEquals(ORIGINAL_URL, result);
    }

    /** Tests that the in-memory access token is cleared when token exchange fails. */
    public void testResolveClearsAccessTokenOnFailure() {
        when(this.mockTokenExchangeService.getResourceToken(ORIGINAL_URL, ACCESS_TOKEN))
                .thenReturn(null);

        // Verify token is set before the call
        Assert.assertEquals(ACCESS_TOKEN, PluginSettings.getInstance().getAccessToken());

        SignedUrlResolver resolver = new SignedUrlResolver(this.mockTokenExchangeService, ACCESS_TOKEN);
        resolver.resolve(ORIGINAL_URL);

        // Token should be cleared after failure
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
        Assert.assertFalse(PluginSettings.getInstance().isRegistered());
    }

    /** Tests that the token exchange service is called with the correct arguments. */
    public void testResolvePassesCorrectArguments() {
        when(this.mockTokenExchangeService.getResourceToken(anyString(), anyString()))
                .thenReturn(SIGNED_URL);

        SignedUrlResolver resolver = new SignedUrlResolver(this.mockTokenExchangeService, ACCESS_TOKEN);
        resolver.resolve(ORIGINAL_URL);

        verify(this.mockTokenExchangeService).getResourceToken(ORIGINAL_URL, ACCESS_TOKEN);
    }

    /**
     * Tests that multiple consecutive calls each invoke the token exchange service independently.
     */
    public void testResolveCalledMultipleTimes() {
        String url1 = "https://cti.wazuh.com/resource/1";
        String url2 = "https://cti.wazuh.com/resource/2";
        String signed1 = "https://cti.wazuh.com/resource/1?verify=abc";
        String signed2 = "https://cti.wazuh.com/resource/2?verify=def";

        when(this.mockTokenExchangeService.getResourceToken(url1, ACCESS_TOKEN)).thenReturn(signed1);
        when(this.mockTokenExchangeService.getResourceToken(url2, ACCESS_TOKEN)).thenReturn(signed2);

        SignedUrlResolver resolver = new SignedUrlResolver(this.mockTokenExchangeService, ACCESS_TOKEN);

        Assert.assertEquals(signed1, resolver.resolve(url1));
        Assert.assertEquals(signed2, resolver.resolve(url2));
        verify(this.mockTokenExchangeService, times(2)).getResourceToken(anyString(), anyString());
    }

    /**
     * Tests that after one failure clears the token, a subsequent resolve still falls back correctly.
     */
    public void testResolveAfterTokenCleared() {
        when(this.mockTokenExchangeService.getResourceToken(anyString(), anyString()))
                .thenReturn(null);

        SignedUrlResolver resolver = new SignedUrlResolver(this.mockTokenExchangeService, ACCESS_TOKEN);

        // First call clears the token
        String result1 = resolver.resolve(ORIGINAL_URL);
        Assert.assertEquals(ORIGINAL_URL, result1);
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());

        // Second call still falls back (resolver holds its own copy of the token)
        String result2 = resolver.resolve(ORIGINAL_URL);
        Assert.assertEquals(ORIGINAL_URL, result2);
    }
}
