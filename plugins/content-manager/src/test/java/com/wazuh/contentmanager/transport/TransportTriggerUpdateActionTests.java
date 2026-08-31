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
import org.opensearch.env.Environment;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;
import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.TriggerUpdateRequest;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.engine.service.EngineService;
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

    /**
     * Integration-style test wiring a real (non-mocked) {@link CatalogSyncJob} into the transport
     * action, proving the 409 Conflict path reflects the job's genuine semaphore state rather than a
     * stubbed {@code isRunning()} return value. A never-running executor keeps the first triggered
     * pass "in flight" so the second REST-level request is deterministically rejected.
     */
    public void testDoExecute_concurrentRequests_secondIsRejectedByRealSemaphore() throws Exception {
        ExecutorService neverRunsExecutor = mock(ExecutorService.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.generic()).thenReturn(neverRunsExecutor);

        CatalogSyncJob realCatalogSyncJob =
                new CatalogSyncJob(
                        mock(Client.class),
                        mock(ConsumersIndex.class),
                        mock(Environment.class),
                        threadPool,
                        mock(EngineService.class),
                        mock(SpaceService.class),
                        mock(SecurityAnalyticsService.class),
                        mock(UserOverridesService.class));
        TransportTriggerUpdateAction realAction =
                new TransportTriggerUpdateAction(
                        mock(TransportService.class), mock(ActionFilters.class), realCatalogSyncJob);

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> firstListener = mock(ActionListener.class);
        realAction.doExecute(mock(Task.class), new TriggerUpdateRequest(), firstListener);
        verify(firstListener)
                .onResponse(argThat(response -> response.getStatus() == RestStatus.ACCEPTED));
        Assert.assertTrue(
                "The real CatalogSyncJob must be running after the first accepted request",
                realCatalogSyncJob.isRunning());

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> secondListener = mock(ActionListener.class);
        realAction.doExecute(mock(Task.class), new TriggerUpdateRequest(), secondListener);

        verify(secondListener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.CONFLICT, response.getStatus());
                                    Assert.assertEquals(
                                            "A content update is already in progress.", response.getMessage());
                                    return true;
                                }));
        verify(neverRunsExecutor, times(1)).execute(any());
    }
}
