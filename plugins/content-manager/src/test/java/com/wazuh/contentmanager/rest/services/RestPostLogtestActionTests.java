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
package com.wazuh.contentmanager.rest.services;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.engine.services.EngineServiceImpl;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestPostLogtestAction} class. This test suite validates the REST API
 * endpoint responsible for running CTI Logtests.
 *
 * <p>Tests verify Logtest requests, proper handling of Logtest data, and appropriate HTTP response
 * codes for successful Logtest requests and validation errors.
 */
public class RestPostLogtestActionTests extends OpenSearchTestCase {
    private EngineService engine;
    private RestPostLogtestAction action;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.engine = mock(EngineServiceImpl.class);
        this.action = new RestPostLogtestAction(this.engine);
    }

    /**
     * Test the {@link RestPostLogtestAction#handleRequest(RestRequest)} method when the request is
     * complete. The expected response is: {200, RestResponse}
     */
    public void testPostLogtest200() {
        // Construct a valid payload to trigger 200 response
        // spotless:off
        JsonNode payload = FixtureFactory.from(
        """
            {
              "queue": 1,
              "location": "/var/log/auth.log",
              "agent_metadata": {},
              "event": "Dec 19 12:00:00 host sshd[123]: Failed password for root from 10.0.0.1 port 12345 ssh2",
              "trace_level": "NONE"
            }
            """
        );
        // spotless:on

        // Mock the 200 response from the Wazuh Engine
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.OK.getStatus());
        // spotless:off
        expectedResponse.setMessage(
            """
            {
              "status": "OK",
              "result": {
                "output": "{\\"wazuh\\":{\\"protocol\\":{\\"queue\\":1,\\"location\\":\\"syscheck\\"},\\"integration\\":{\\"category\\":\\"Security\\",\\"name\\":\\"integration/wazuh-core/0\\",\\"decoders\\":[\\"core-wazuh-message\\",\\"integrations\\"]}},\\"name\\":\\"nahuel\\",\\"event\\":{\\"original\\":\\"File /etc/passwd modified\\"},\\"@timestamp\\":\\"2025-12-26T17:33:22Z\\"}",
                "asset_traces": [
                  {
                    "asset": "decoder/core-wazuh-message/0",
                    "success": true,
                    "traces": [
                      "@timestamp: get_date -> Success"
                    ]
                  }
                ]
              }
            }
            """
        );
        // spotless:on
        when(this.engine.logtest(payload)).thenReturn(expectedResponse);

        // Invoke the method under test
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(payload.toString().getBytes()));
        RestResponse actualResponse = this.action.handleRequest(request);

        // Assert the response is expected
        assertEquals(expectedResponse, actualResponse);
        verify(this.engine, times(1)).logtest(any(JsonNode.class));
    }

    /** Test that requests with no payload are handled properly, returning a 400 status code. */
    public void testPostLogTest400_noPayload() {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("JSON request body is required.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(false);
        when(request.content()).thenReturn(null);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Test the {@link RestPostLogtestAction#handleRequest(RestRequest)} method when the logtest has
     * not been created (mock). The expected response is: {400, RestResponse}
     */
    public void testPostLogtest400() {
        // Construct a bad payload to trigger 400 response
        // spotless:off
        JsonNode payload = FixtureFactory.from(
        """
            {
              "queue": 1,
              "location": "syscheck",
              "event": "File /etc/passwd modified",
              "trace_level": "ALL"
            }
            """
        );
        // spotless:on

        // Mock the 400 response from the Wazuh Engine
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        // spotless:off
        expectedResponse.setMessage(
            """
            {
              "status": "ERROR",
              "error": "agent_metadata is required and must be a JSON object"
            }
            """
        );
        // spotless:on
        when(this.engine.logtest(payload)).thenReturn(expectedResponse);

        // Create a RestRequest with the bad payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(payload.toString().getBytes()));

        // Call the method under test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Assert the response is expected
        assertEquals(expectedResponse, actualResponse);
        verify(this.engine, times(1)).logtest(any(JsonNode.class));
    }

    /**
     * Test the {@link RestPostLogtestAction#handleRequest(RestRequest)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     */
    public void testPostLogtest500() {
        // Construct a bad payload to trigger 500 response
        // This one is missing a value for location
        // spotless:off
        JsonNode payload = FixtureFactory.from(
        """
            {
              "queue": 1,
              "location": "/var/log/auth.log",
              "agent_metadata": {},
              "event": "Dec 19 12:00:00 host sshd[123]: Failed password for root from 10.0.0.1 port 12345 ssh2",
              "trace_level": "NONE"
            }
            """
        );
        // spotless:on

        // Mock the 500 response from the Wazuh Engine
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        // spotless:off
        expectedResponse.setMessage(
            """
            {
              "status": "ERROR",
              "error": "agent_metadata is required and must be a JSON object"
            }
            """
        );
        // spotless:on
        when(this.engine.logtest(payload)).thenReturn(expectedResponse);

        // Create a RestRequest with the bad payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(payload.toString().getBytes()));

        // Call the method under test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Assert the response is expected
        assertEquals(expectedResponse, actualResponse);
        verify(this.engine, times(1)).logtest(any(JsonNode.class));
    }
}
