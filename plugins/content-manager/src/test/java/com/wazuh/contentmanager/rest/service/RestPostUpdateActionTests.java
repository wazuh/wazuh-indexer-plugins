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
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.lang.reflect.Field;

import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.*;

public class RestPostUpdateActionTests extends OpenSearchTestCase {
    private CatalogSyncJob catalogSyncJob;
    private RestPostUpdateAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);
        this.catalogSyncJob = mock(CatalogSyncJob.class);
        this.action = new RestPostUpdateAction(this.catalogSyncJob);
    }

    @After
    public void tearDown() throws Exception {
        clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    /** access_token set and no job running → 202 with exact success message */
    public void testHandleRequest_Accepted() throws IOException {
        PluginSettings.getInstance().setAccessToken("valid-token");
        when(this.catalogSyncJob.isRunning()).thenReturn(false);

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.ACCEPTED, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("The update request has been accepted for processing."));
        verify(this.catalogSyncJob, times(1)).trigger();
    }

    /**
     * access_token set but job already running → 409 with exact conflict message, trigger NOT called
     */
    public void testHandleRequest_Conflict() throws IOException {
        PluginSettings.getInstance().setAccessToken("valid-token");
        when(this.catalogSyncJob.isRunning()).thenReturn(true);

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.CONFLICT, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("A content update is already in progress."));
        verify(this.catalogSyncJob, never()).trigger();
    }
}
