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
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.action.IndexSubscriptionRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.cti.catalog.service.SubscriptionServiceImpl;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.Mockito.*;

public class TransportIndexSubscriptionActionTests extends OpenSearchTestCase {
    private SubscriptionServiceImpl subscriptionService;
    private TransportIndexSubscriptionAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.subscriptionService = mock(SubscriptionServiceImpl.class);
        this.action =
                new TransportIndexSubscriptionAction(
                        mock(TransportService.class), mock(ActionFilters.class), this.subscriptionService);
    }

    public void testDoExecute_Created() throws Exception {
        IndexSubscriptionRequest request = new IndexSubscriptionRequest("valid-token");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(this.subscriptionService, times(1)).register("valid-token");
        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.CREATED, response.getStatus());
                                    Assert.assertEquals(Constants.S_201_ACCESS_TOKEN_RECEIVED, response.getMessage());
                                    return true;
                                }));
    }

    public void testDoExecute_PreconditionFailed() throws Exception {
        doThrow(new IllegalStateException(Constants.E_412_UNPROTECTED_CREDENTIALS_INDEX))
                .when(this.subscriptionService)
                .register(anyString());
        IndexSubscriptionRequest request = new IndexSubscriptionRequest("valid-token");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.PRECONDITION_FAILED, response.getStatus());
                                    Assert.assertEquals(
                                            Constants.E_412_UNPROTECTED_CREDENTIALS_INDEX, response.getMessage());
                                    return true;
                                }));
    }

    public void testDoExecute_OtherIllegalState() throws Exception {
        IllegalStateException cause = new IllegalStateException("Some other illegal state");
        doThrow(cause).when(this.subscriptionService).register(anyString());
        IndexSubscriptionRequest request = new IndexSubscriptionRequest("valid-token");

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener).onFailure(cause);
        verify(listener, never()).onResponse(any());
    }

    public void testDoExecute_Exception() throws Exception {
        doThrow(new RuntimeException("Unexpected failure"))
                .when(this.subscriptionService)
                .register(anyString());
        IndexSubscriptionRequest request = new IndexSubscriptionRequest("valid-token");

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
