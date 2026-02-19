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

import org.junit.Assert;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Subscription;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestPostSubscriptionAction} class. This test suite validates the REST
 * API endpoint responsible for creating new CTI subscriptions.
 *
 * <p>Tests verify subscription creation requests, proper handling of subscription data, and
 * appropriate HTTP response codes for successful subscription creation and validation errors.
 */
public class RestPostSubscriptionActionTests extends OpenSearchTestCase {
    private CtiConsole console;
    private RestPostSubscriptionAction action;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.console = mock(CtiConsole.class);
        this.action = new RestPostSubscriptionAction(this.console);
    }

    /**
     * Test the {@link RestPostSubscriptionAction#handleRequest(Subscription)} method when the request
     * is complete. The expected response is: {201, RestResponse}
     *
     * @throws IOException
     */
    public void testPostToken201() throws IOException {
        // Mock
        Subscription subscription = new Subscription();

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(subscription);

        // Expected response
        RestResponse expectedResponse =
                new RestResponse("Subscription created successfully", RestStatus.CREATED.getStatus());

        // Assert
        Assert.assertTrue(
                bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        Assert.assertTrue(
                bytesRestResponse
                        .content()
                        .utf8ToString()
                        .contains(String.valueOf(expectedResponse.getStatus())));
        Assert.assertEquals(RestStatus.CREATED, bytesRestResponse.status());
    }

    /**
     * Test the {@link RestPostSubscriptionAction#handleRequest(Subscription)} method when the token
     * has not been created (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testPostToken400() throws IOException {
        // Mock
        Subscription subscription = new Subscription();
        doThrow(new IllegalArgumentException("Missing required parameters"))
                .when(this.console)
                .onPostSubscriptionRequest(subscription);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(subscription);

        // Expected response
        RestResponse expectedResponse =
                new RestResponse("Missing required parameters", RestStatus.BAD_REQUEST.getStatus());

        // Assert
        Assert.assertTrue(
                bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        Assert.assertTrue(
                bytesRestResponse
                        .content()
                        .utf8ToString()
                        .contains(String.valueOf(expectedResponse.getStatus())));
        Assert.assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
    }
}
