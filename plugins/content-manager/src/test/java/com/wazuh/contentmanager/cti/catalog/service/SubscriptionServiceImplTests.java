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
package com.wazuh.contentmanager.cti.catalog.service;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;

import com.wazuh.contentmanager.cti.catalog.index.CredentialsIndex;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.PlansService;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class SubscriptionServiceImplTests extends OpenSearchTestCase {

    private PlansService plansService;
    private CredentialsIndex credentialsIndex;
    private SubscriptionServiceImpl service;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(org.opensearch.common.settings.Settings.EMPTY);
        this.plansService = mock(PlansService.class);
        this.credentialsIndex = mock(CredentialsIndex.class);
        this.service = new SubscriptionServiceImpl(this.plansService, this.credentialsIndex, true);
    }

    @After
    public void tearDown() throws Exception {
        clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field f = PluginSettings.class.getDeclaredField("INSTANCE");
        f.setAccessible(true);
        f.set(null, null);
    }

    /** Token present and valid → returns plan from getMyPlan(); does not fall back. */
    public void testGetPlan_ValidToken() {
        PluginSettings.getInstance().setAccessToken("valid-token");
        Plan plan = mock(Plan.class);
        when(this.plansService.getMyPlan(any(Token.class))).thenReturn(plan);

        Plan result = this.service.getPlan();

        Assert.assertSame(plan, result);
        ArgumentCaptor<Token> tokenCaptor = ArgumentCaptor.forClass(Token.class);
        verify(this.plansService).getMyPlan(tokenCaptor.capture());
        Assert.assertEquals("valid-token", tokenCaptor.getValue().getAccessToken());
        Assert.assertEquals("Bearer", tokenCaptor.getValue().getTokenType());
        verify(this.plansService, never()).getPlan();
    }

    /**
     * Token present but getMyPlan() returns null (invalid token) → deletes credentials document,
     * clears in-memory token, and falls back to the public plan.
     */
    public void testGetPlan_InvalidToken_FallsBackToPublicPlan() throws Exception {
        PluginSettings.getInstance().setAccessToken("bad-token");
        when(this.plansService.getMyPlan(any(Token.class))).thenReturn(null);
        Plan publicPlan = mock(Plan.class);
        when(this.plansService.getPlan()).thenReturn(publicPlan);

        Plan result = this.service.getPlan();

        Assert.assertSame(publicPlan, result);
        verify(this.credentialsIndex).deleteDocument();
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
    }

    /** No token in PluginSettings → calls getPlan() directly without attempting getMyPlan(). */
    public void testGetPlan_NoToken() {
        Plan publicPlan = mock(Plan.class);
        when(this.plansService.getPlan()).thenReturn(publicPlan);

        Plan result = this.service.getPlan();

        Assert.assertSame(publicPlan, result);
        verify(this.plansService, never()).getMyPlan(any());
        verify(this.plansService).getPlan();
    }

    /** register() persists credentials and updates the in-memory token. */
    public void testRegister() throws Exception {
        this.service.register("new-token");

        verify(this.credentialsIndex).storeCredentials("new-token");
        Assert.assertEquals("new-token", PluginSettings.getInstance().getAccessToken());
    }

    /**
     * Token invalid and deleteDocument() throws → exception is swallowed, token still cleared, falls
     * back to public plan.
     */
    public void testGetPlan_InvalidToken_DeleteThrows_StillFallsBackToPublicPlan() throws Exception {
        PluginSettings.getInstance().setAccessToken("bad-token");
        when(this.plansService.getMyPlan(any(Token.class))).thenReturn(null);
        doThrow(new RuntimeException("index gone")).when(this.credentialsIndex).deleteDocument();
        Plan publicPlan = mock(Plan.class);
        when(this.plansService.getPlan()).thenReturn(publicPlan);

        Plan result = this.service.getPlan();

        Assert.assertSame(publicPlan, result);
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
    }

    /** unregister() deletes the credentials document and clears the in-memory token. */
    public void testUnregister() throws Exception {
        PluginSettings.getInstance().setAccessToken("existing-token");

        this.service.unregister();

        verify(this.credentialsIndex).deleteDocument();
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
    }
}
