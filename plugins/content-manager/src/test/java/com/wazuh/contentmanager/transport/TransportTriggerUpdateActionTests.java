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
package com.wazuh.contentmanager.transport;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;

import com.wazuh.contentmanager.action.TriggerUpdateRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.*;

public class TransportTriggerUpdateActionTests extends OpenSearchTestCase {
    private CatalogSyncJob catalogSyncJob;
    private TransportTriggerUpdateAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);
        this.catalogSyncJob = mock(CatalogSyncJob.class);
        this.action =
                new TransportTriggerUpdateAction(
                        mock(TransportService.class), mock(ActionFilters.class), this.catalogSyncJob);
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

    public void testDoExecute_Accepted() {
        when(this.catalogSyncJob.isRunning()).thenReturn(false);
        TriggerUpdateRequest request = new TriggerUpdateRequest();

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.ACCEPTED, response.getStatus());
                                    Assert.assertEquals(
                                            "The update request has been accepted for processing.",
                                            response.getMessage());
                                    return true;
                                }));
        verify(this.catalogSyncJob, times(1)).trigger();
    }

    public void testDoExecute_Conflict() {
        when(this.catalogSyncJob.isRunning()).thenReturn(true);
        TriggerUpdateRequest request = new TriggerUpdateRequest();

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.CONFLICT, response.getStatus());
                                    Assert.assertEquals(
                                            "A content update is already in progress.", response.getMessage());
                                    return true;
                                }));
        verify(this.catalogSyncJob, never()).trigger();
    }

    public void testDoExecute_Exception() {
        when(this.catalogSyncJob.isRunning()).thenThrow(new RuntimeException("Unexpected failure"));
        TriggerUpdateRequest request = new TriggerUpdateRequest();

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.getStatus());
                                    Assert.assertEquals("Unexpected failure", response.getMessage());
                                    return true;
                                }));
    }
}
