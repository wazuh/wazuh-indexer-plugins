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

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestDeleteSubscriptionAction} class. This test suite validates the REST
 * API endpoint responsible for deleting CTI subscription tokens.
 *
 * <p>Tests verify token deletion requests, proper cleanup of authentication state, and appropriate
 * HTTP response codes for successful deletions and missing token scenarios.
 */
public class RestDeleteSubscriptionActionTests extends OpenSearchTestCase {
    private CtiConsole console;
    private RestDeleteSubscriptionAction action;

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
        this.action = new RestDeleteSubscriptionAction(this.console);
    }

    /**
     * Test the {@link RestDeleteSubscriptionAction#handleRequest()} method when the token is created
     * (mock). The expected response is: {200, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteToken200() throws IOException {
        // Mock
        Token token = new Token("test_token", "test_type");
        when(this.console.getToken()).thenReturn(token);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest();

        // Expected response
        RestResponse expectedResponse =
                new RestResponse("Subscription deleted successfully", RestStatus.OK.getStatus());

        // Assert
        Assert.assertTrue(
                bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        Assert.assertTrue(
                bytesRestResponse
                        .content()
                        .utf8ToString()
                        .contains(String.valueOf(expectedResponse.getStatus())));
        Assert.assertEquals(RestStatus.OK, bytesRestResponse.status());
    }

    /**
     * Test the {@link RestDeleteSubscriptionAction#handleRequest()} method when the token has not
     * been created (mock). The expected response is: {404, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteToken404() throws IOException {
        // Mock
        when(this.console.getToken()).thenReturn(null);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest();

        // Expected response
        RestResponse expectedResponse =
                new RestResponse("Token not found", RestStatus.NOT_FOUND.getStatus());

        // Assert
        Assert.assertTrue(
                bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        Assert.assertTrue(
                bytesRestResponse
                        .content()
                        .utf8ToString()
                        .contains(String.valueOf(expectedResponse.getStatus())));
        Assert.assertEquals(RestStatus.NOT_FOUND, bytesRestResponse.status());
    }
}
