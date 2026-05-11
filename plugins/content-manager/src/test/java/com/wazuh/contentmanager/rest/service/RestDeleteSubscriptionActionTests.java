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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;

import com.wazuh.contentmanager.cti.catalog.service.SubscriptionService;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RestDeleteSubscriptionAction}.
 *
 * <p>Validates credential removal and error handling via a mocked {@link SubscriptionService}.
 */
public class RestDeleteSubscriptionActionTests extends OpenSearchTestCase {
    private SubscriptionService subscriptionService;
    private RestDeleteSubscriptionAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(org.opensearch.common.settings.Settings.EMPTY);
        this.subscriptionService = mock(SubscriptionService.class);
        this.action = new RestDeleteSubscriptionAction(this.subscriptionService);
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

    /** Successful deletion returns 200 "Credentials removed" and delegates to unregister(). */
    public void testDeleteSubscription200() throws Exception {
        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.OK, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("Credentials removed"));
        Assert.assertTrue(body.contains("200"));
        verify(this.subscriptionService, times(1)).unregister();
    }

    /** When unregister() throws, returns 500 with the error message. */
    public void testDeleteSubscription500() throws Exception {
        doThrow(new RuntimeException("Delete failed")).when(this.subscriptionService).unregister();

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
        Assert.assertTrue(response.content().utf8ToString().contains("Delete failed"));
    }
}
