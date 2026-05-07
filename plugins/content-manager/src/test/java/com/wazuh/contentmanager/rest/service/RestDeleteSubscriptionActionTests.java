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

import com.wazuh.contentmanager.cti.catalog.index.CredentialsIndex;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RestDeleteSubscriptionAction}.
 *
 * <p>Validates credential removal, in-memory token cleanup, and error handling.
 */
public class RestDeleteSubscriptionActionTests extends OpenSearchTestCase {
    private CredentialsIndex credentialsIndex;
    private RestDeleteSubscriptionAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(org.opensearch.common.settings.Settings.EMPTY);
        this.credentialsIndex = mock(CredentialsIndex.class);
        this.action = new RestDeleteSubscriptionAction(this.credentialsIndex);
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

    /** Successful deletion returns 200 "Credentials removed" and clears the in-memory token. */
    public void testDeleteCredentials200() throws Exception {
        PluginSettings.getInstance().setAccessToken("some-token");

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.OK, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("Credentials removed"));
        Assert.assertTrue(body.contains("200"));
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
        verify(this.credentialsIndex, times(1)).deleteIndex();
    }

    /** When deleteIndex() throws, returns 500 with the error message. */
    public void testDeleteCredentials500() throws Exception {
        doThrow(new RuntimeException("Index not ready")).when(this.credentialsIndex).deleteIndex();

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
        Assert.assertTrue(response.content().utf8ToString().contains("Index not ready"));
    }
}
