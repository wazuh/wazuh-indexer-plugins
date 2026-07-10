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

import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.core.action.ActionListener;
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

    /** register() persists credentials and updates the in-memory token. */
    public void testRegister() throws Exception {
        this.service.register("new-token");

        verify(this.credentialsIndex).storeCredentials("new-token");
        Assert.assertEquals("new-token", PluginSettings.getInstance().getAccessToken());
    }

    /** Async getPlan: token in memory and valid → returns plan from getMyPlan(). */
    @SuppressWarnings("unchecked")
    public void testGetPlanAsync_ValidToken() {
        PluginSettings.getInstance().setAccessToken("valid-token");
        Plan plan = mock(Plan.class);
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(1);
                            asyncListener.onResponse(plan);
                            return null;
                        })
                .when(this.plansService)
                .getMyPlan(any(Token.class), any(ActionListener.class));

        ActionListener<Plan> listener = mock(ActionListener.class);
        this.service.getPlan(listener);

        verify(listener).onResponse(plan);
    }

    /** Async getPlan: token in memory but getMyPlan returns null → deletes and falls back. */
    @SuppressWarnings("unchecked")
    public void testGetPlanAsync_InvalidToken_FallsBackToPublicPlan() {
        PluginSettings.getInstance().setAccessToken("bad-token");
        Plan publicPlan = mock(Plan.class);
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(1);
                            asyncListener.onResponse(null);
                            return null;
                        })
                .when(this.plansService)
                .getMyPlan(any(Token.class), any(ActionListener.class));
        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> asyncListener = invocation.getArgument(0);
                            asyncListener.onResponse(null);
                            return null;
                        })
                .when(this.credentialsIndex)
                .deleteDocument(any(ActionListener.class));
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(0);
                            asyncListener.onResponse(publicPlan);
                            return null;
                        })
                .when(this.plansService)
                .getPlan(any(ActionListener.class));

        ActionListener<Plan> listener = mock(ActionListener.class);
        this.service.getPlan(listener);

        verify(listener).onResponse(publicPlan);
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
    }

    /** Async getPlan: no token in memory or index → returns public plan. */
    @SuppressWarnings("unchecked")
    public void testGetPlanAsync_NoToken() {
        Plan publicPlan = mock(Plan.class);
        doAnswer(
                        invocation -> {
                            ActionListener<Boolean> asyncListener = invocation.getArgument(0);
                            asyncListener.onResponse(false);
                            return null;
                        })
                .when(this.credentialsIndex)
                .exists(any(ActionListener.class));
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(0);
                            asyncListener.onResponse(publicPlan);
                            return null;
                        })
                .when(this.plansService)
                .getPlan(any(ActionListener.class));

        ActionListener<Plan> listener = mock(ActionListener.class);
        this.service.getPlan(listener);

        verify(listener).onResponse(publicPlan);
        verify(this.plansService, never()).getMyPlan(any(Token.class), any(ActionListener.class));
    }

    /** Async getPlan: invalid token and deleteDocument fails → still falls back to public plan. */
    @SuppressWarnings("unchecked")
    public void testGetPlanAsync_InvalidToken_DeleteFails_StillFallsBack() {
        PluginSettings.getInstance().setAccessToken("bad-token");
        Plan publicPlan = mock(Plan.class);
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(1);
                            asyncListener.onResponse(null);
                            return null;
                        })
                .when(this.plansService)
                .getMyPlan(any(Token.class), any(ActionListener.class));
        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> asyncListener = invocation.getArgument(0);
                            asyncListener.onFailure(new RuntimeException("index gone"));
                            return null;
                        })
                .when(this.credentialsIndex)
                .deleteDocument(any(ActionListener.class));
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(0);
                            asyncListener.onResponse(publicPlan);
                            return null;
                        })
                .when(this.plansService)
                .getPlan(any(ActionListener.class));

        ActionListener<Plan> listener = mock(ActionListener.class);
        this.service.getPlan(listener);

        verify(listener).onResponse(publicPlan);
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
    }

    /** Async unregister() deletes the credentials document and clears the in-memory token. */
    @SuppressWarnings("unchecked")
    public void testUnregisterAsync() {
        PluginSettings.getInstance().setAccessToken("existing-token");

        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> asyncListener = invocation.getArgument(0);
                            asyncListener.onResponse(null);
                            return null;
                        })
                .when(this.credentialsIndex)
                .deleteDocument(any(ActionListener.class));

        ActionListener<Void> listener = mock(ActionListener.class);
        this.service.unregister(listener);

        verify(this.credentialsIndex).deleteDocument(any(ActionListener.class));
        verify(listener).onResponse(null);
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
    }

    /** Async unregister() propagates failure from the credentials index. */
    @SuppressWarnings("unchecked")
    public void testUnregisterAsync_Failure() {
        PluginSettings.getInstance().setAccessToken("existing-token");
        RuntimeException cause = new RuntimeException("delete failed");

        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> asyncListener = invocation.getArgument(0);
                            asyncListener.onFailure(cause);
                            return null;
                        })
                .when(this.credentialsIndex)
                .deleteDocument(any(ActionListener.class));

        ActionListener<Void> listener = mock(ActionListener.class);
        this.service.unregister(listener);

        verify(listener).onFailure(cause);
        Assert.assertEquals("existing-token", PluginSettings.getInstance().getAccessToken());
    }
}
