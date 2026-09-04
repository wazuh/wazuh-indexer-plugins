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

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.action.LogtestDetectionRequest;
import com.wazuh.contentmanager.action.LogtestResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.LogtestService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class TransportLogtestDetectionActionTests extends OpenSearchTestCase {
    private LogtestService logtestService;
    private ThreadPool threadPool;
    private TransportLogtestDetectionAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.logtestService = mock(LogtestService.class);
        this.threadPool = mock(ThreadPool.class);
        // Execute submitted work synchronously so the existing assertions still observe the result.
        when(this.threadPool.executor(anyString()))
                .thenReturn(OpenSearchExecutors.newDirectExecutorService());
        this.action =
                new TransportLogtestDetectionAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        this.threadPool,
                        this.logtestService);
    }

    @SuppressWarnings("unchecked")
    public void testDoExecute_Success() {
        doAnswer(
                        invocation -> {
                            ActionListener<RestResponse> l = invocation.getArgument(3);
                            l.onResponse(new RestResponse("OK", RestStatus.OK.getStatus()));
                            return null;
                        })
                .when(this.logtestService)
                .executeDetectionAsync(
                        eq("my-integration"), eq(Space.TEST), any(JsonNode.class), any(ActionListener.class));

        String body =
                "{\"space\":\"test\",\"integration\":\"my-integration\",\"input\":{\"key\":\"value\"}}";
        LogtestDetectionRequest request = new LogtestDetectionRequest(body);

        ActionListener<LogtestResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    return true;
                                }));
    }

    public void testDoExecute_InvalidJson() {
        LogtestDetectionRequest request = new LogtestDetectionRequest("not json");

        @SuppressWarnings("unchecked")
        ActionListener<LogtestResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    return true;
                                }));
    }

    public void testDoExecute_MissingRequiredFields() {
        LogtestDetectionRequest request = new LogtestDetectionRequest("{\"space\":\"test\"}");

        @SuppressWarnings("unchecked")
        ActionListener<LogtestResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    return true;
                                }));
    }

    public void testDoExecute_InvalidSpace() {
        String body = "{\"space\":\"invalid\",\"integration\":\"int-1\",\"input\":{\"key\":\"value\"}}";
        LogtestDetectionRequest request = new LogtestDetectionRequest(body);

        @SuppressWarnings("unchecked")
        ActionListener<LogtestResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    return true;
                                }));
    }

    public void testDoExecute_DraftSpaceNotAllowed() {
        String body = "{\"space\":\"draft\",\"integration\":\"int-1\",\"input\":{\"key\":\"value\"}}";
        LogtestDetectionRequest request = new LogtestDetectionRequest(body);

        @SuppressWarnings("unchecked")
        ActionListener<LogtestResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    return true;
                                }));
    }

    public void testDoExecute_InputNotObject() {
        String body = "{\"space\":\"test\",\"integration\":\"int-1\",\"input\":\"not-an-object\"}";
        LogtestDetectionRequest request = new LogtestDetectionRequest(body);

        @SuppressWarnings("unchecked")
        ActionListener<LogtestResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
                                    return true;
                                }));
    }

    @SuppressWarnings("unchecked")
    public void testDoExecute_Exception() {
        doAnswer(
                        invocation -> {
                            ActionListener<RestResponse> l = invocation.getArgument(3);
                            l.onFailure(new RuntimeException("Unexpected"));
                            return null;
                        })
                .when(this.logtestService)
                .executeDetectionAsync(any(), any(), any(), any(ActionListener.class));

        String body = "{\"space\":\"test\",\"integration\":\"int-1\",\"input\":{\"key\":\"value\"}}";
        LogtestDetectionRequest request = new LogtestDetectionRequest(body);

        ActionListener<LogtestResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.getStatus());
                                    return true;
                                }));
    }
}
