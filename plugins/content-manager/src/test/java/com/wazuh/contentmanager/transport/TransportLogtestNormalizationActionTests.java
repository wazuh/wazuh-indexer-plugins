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

import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.action.LogtestNormalizationRequest;
import com.wazuh.contentmanager.action.LogtestResponse;
import com.wazuh.contentmanager.cti.catalog.service.LogtestService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.Mockito.*;

public class TransportLogtestNormalizationActionTests extends OpenSearchTestCase {
    private LogtestService logtestService;
    private TransportLogtestNormalizationAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.logtestService = mock(LogtestService.class);
        this.action =
                new TransportLogtestNormalizationAction(
                        mock(TransportService.class), mock(ActionFilters.class), this.logtestService);
    }

    public void testDoExecute_Success() {
        when(this.logtestService.executeNormalization(any(ObjectNode.class)))
                .thenReturn(new RestResponse("OK", RestStatus.OK.getStatus()));

        LogtestNormalizationRequest request = new LogtestNormalizationRequest("{\"space\":\"test\"}");

        @SuppressWarnings("unchecked")
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
        LogtestNormalizationRequest request = new LogtestNormalizationRequest("not json");

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

    public void testDoExecute_MissingSpace() {
        LogtestNormalizationRequest request = new LogtestNormalizationRequest("{\"other\":\"val\"}");

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
        LogtestNormalizationRequest request =
                new LogtestNormalizationRequest("{\"space\":\"invalid\"}");

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
        LogtestNormalizationRequest request = new LogtestNormalizationRequest("{\"space\":\"draft\"}");

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

    public void testDoExecute_Exception() {
        when(this.logtestService.executeNormalization(any()))
                .thenThrow(new RuntimeException("Unexpected"));

        LogtestNormalizationRequest request = new LogtestNormalizationRequest("{\"space\":\"test\"}");

        @SuppressWarnings("unchecked")
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
