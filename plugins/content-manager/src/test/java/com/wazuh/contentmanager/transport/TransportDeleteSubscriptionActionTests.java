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

import com.wazuh.contentmanager.action.DeleteSubscriptionRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.cti.catalog.service.SubscriptionServiceImpl;

import static org.mockito.Mockito.*;

public class TransportDeleteSubscriptionActionTests extends OpenSearchTestCase {
    private SubscriptionServiceImpl subscriptionService;
    private TransportDeleteSubscriptionAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.subscriptionService = mock(SubscriptionServiceImpl.class);
        this.action =
                new TransportDeleteSubscriptionAction(
                        mock(TransportService.class), mock(ActionFilters.class), this.subscriptionService);
    }

    public void testDoExecute_OK() throws Exception {
        DeleteSubscriptionRequest request = new DeleteSubscriptionRequest();

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(this.subscriptionService, times(1)).unregister();
        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    Assert.assertEquals("Credentials removed", response.getMessage());
                                    return true;
                                }));
    }

    public void testDoExecute_Exception() throws Exception {
        doThrow(new RuntimeException("Unexpected failure")).when(this.subscriptionService).unregister();
        DeleteSubscriptionRequest request = new DeleteSubscriptionRequest();

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

    public void testDoExecute_ExceptionNullMessage() throws Exception {
        doThrow(new RuntimeException((String) null)).when(this.subscriptionService).unregister();
        DeleteSubscriptionRequest request = new DeleteSubscriptionRequest();

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.getStatus());
                                    Assert.assertEquals(
                                            "An unexpected error occurred while processing your request.",
                                            response.getMessage());
                                    return true;
                                }));
    }
}
