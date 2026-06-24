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
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;

import com.wazuh.contentmanager.action.DeleteSpaceRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.*;

public class TransportDeleteSpaceActionTests extends OpenSearchTestCase {
    private TransportDeleteSpaceAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        // Enable engine mock so constructor uses MockSecurityAnalyticsService
        Settings settings = Settings.builder().put("plugins.content_manager.engine.mock", true).build();
        PluginSettings.getInstance(settings);
        this.action =
                new TransportDeleteSpaceAction(
                        mock(TransportService.class), mock(ActionFilters.class), mock(Client.class));
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

    public void testDoExecute_InvalidSpace() {
        DeleteSpaceRequest request = new DeleteSpaceRequest("invalid_space");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Invalid space"));
                                    return true;
                                }));
    }

    public void testDoExecute_NonDraftSpace() {
        DeleteSpaceRequest request = new DeleteSpaceRequest("standard");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Cannot reset"));
                                    return true;
                                }));
    }

    public void testDoExecute_TestSpaceNotAllowed() {
        DeleteSpaceRequest request = new DeleteSpaceRequest("test");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    Assert.assertTrue(response.getMessage().contains("Cannot reset"));
                                    return true;
                                }));
    }
}
