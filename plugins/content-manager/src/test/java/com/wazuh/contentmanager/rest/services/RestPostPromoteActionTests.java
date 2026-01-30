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
package com.wazuh.contentmanager.rest.services;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.nio.charset.StandardCharsets;

import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestPostPromoteAction} class. This test suite validates the REST API
 * endpoint responsible for running CTI Promotes.
 *
 * <p>Tests verify Promote requests, proper handling of Promote data, and appropriate HTTP response
 * codes for successful Promote requests and validation errors.
 */
public class RestPostPromoteActionTests extends OpenSearchTestCase {
    private EngineService engine;
    private SpaceService spaceService;
    private RestPostPromoteAction action;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.engine = mock(EngineService.class);
        this.spaceService = mock(SpaceService.class);
        this.action = new RestPostPromoteAction(this.engine, this.spaceService);
    }

    /**
     * Mock a request for this endpoint.
     *
     * @param content payload to use in the request.
     * @return a request for this endpoint
     */
    private RestRequest createRestRequest(String content) {
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(content.getBytes(StandardCharsets.UTF_8)));
        return request;
    }

    /**
     * Return a valid request for this endpoint.
     *
     * @return valid request for this endpoint
     */
    private RestRequest mockValidRequest() {
        // spotless:off
        String payload = """
                {
                    "space": "draft",
                    "changes": {
                        "policy": [],
                        "integrations": [],
                        "kvdbs": [],
                        "decoders": [{"operation": "add", "id": "12345"}],
                        "filters": []
                    }
                }
                """;
        // spotless:on
        return this.createRestRequest(payload);
    }

    /** If any of the catalog indices do not exist, return a 500 error. */
    public void testPostPromote500_indexNotFound() {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(500);
        expectedResponse.setMessage("Index [.cti-decoders] not found.");

        // Mock request
        RestRequest request = this.mockValidRequest();

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());
        assertTrue(actualResponse.getMessage().contains(expectedResponse.getMessage()));
    }

    /** If the engine does not respond, return a 500 error. */
    public void testPostPromote500_engineUnreachable() {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(500);
        when(this.engine.promote(any(JsonNode.class))).thenReturn(expectedResponse);

        // Mock request
        RestRequest request = this.mockValidRequest();

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());
    }

    /** If an unexpected error happens, return a 500 error. */
    public void testPostPromote500_unexpectedError() {
        /* Engine */
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(500);
        expectedResponse.setMessage("unexpected error");
        when(this.engine.promote(any(JsonNode.class))).thenReturn(expectedResponse);

        // Mock request
        RestRequest request = this.mockValidRequest();

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());

        /* SpaceService */
        when(this.spaceService.getSpaceResources(anyString())).thenThrow(Exception.class);
        actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());
        assertTrue(expectedResponse.getMessage().contains(actualResponse.getMessage()));
    }

    /** If the given space does not exist, or is not promotable, return a 400 error. */
    public void testPostPromote400_invalidSpace() {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(400);
        expectedResponse.setMessage("Unknown space: [invalid].");

        // Mock request
        // spotless:off
        String payload = """
                {
                    "space": "invalid",
                    "changes": {
                        "policy": [],
                        "integrations": [],
                        "kvdbs": [],
                        "decoders": [{"operation": "add", "id": "12345"}],
                        "filters": []
                    }
                }
                """;
        // spotless:on
        RestRequest request = this.createRestRequest(payload);

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());
        assertTrue(actualResponse.getMessage().contains(expectedResponse.getMessage()));
    }

    /** If the given space can not be promotable, return a 400 error. */
    public void testPostPromote400_unpromotableSpace() {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(400);
        expectedResponse.setMessage("Space [standard] cannot be promoted.");

        // Mock request
        // spotless:off
        String payload = """
                {
                    "space": "standard",
                    "changes": {
                        "policy": [],
                        "integrations": [],
                        "kvdbs": [],
                        "decoders": [{"operation": "add", "id": "12345"}],
                        "filters": []
                    }
                }
                """;
        // spotless:on
        RestRequest request = this.createRestRequest(payload);

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());
        assertTrue(actualResponse.getMessage().contains(expectedResponse.getMessage()));
    }

    /** If the request's payload does not contain all the required fields, return a 400 error. */
    public void testPostPromote400_missingContent() {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(400);
        expectedResponse.setMessage("Validation error");

        // Mock request
        // spotless:off
        String payload = """
                {
                    "space": "draft",
                    "changes": {}
                }
                """;
        // spotless:on
        RestRequest request = this.createRestRequest(payload);

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse, actualResponse);
        assertTrue(actualResponse.getMessage().contains(expectedResponse.getMessage()));

        // TODO extend with other invalid cases
    }

    /** If the request's payload is empty, return a 400 error. */
    public void testPostPromote400_emptyContent() {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(400);
        expectedResponse.setMessage(Constants.E_400_JSON_REQUEST_BODY_IS_REQUIRED);

        // Mock request
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(false);

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse, actualResponse);
        assertTrue(actualResponse.getMessage().contains(expectedResponse.getMessage()));
    }

    /** If any of the documents stated in the request is missing, return a 400 error. */
    public void testPostPromote400_missingResource() {
        fail("Not yet implemented");
    }

    /** If the requested operation for the policy is not "update", return a 400 error. */
    public void testPostPromote400_invalidOperationForPolicy() {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(400);
        expectedResponse.setMessage(Constants.E_400_INVALID_PROMOTION_OPERATION_FOR_POLICY);

        // Mock request
        // spotless:off
        String payload = """
                {
                    "space": "test",
                    "changes": {
                        "policy": [{"operation": "add", "id": "12345"}],
                        "integrations": [],
                        "kvdbs": [],
                        "decoders": [],
                        "filters": []
                    }
                }
                """;
        // spotless:on
        RestRequest request = this.createRestRequest(payload);

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());
        assertTrue(actualResponse.getMessage().contains(expectedResponse.getMessage()));
    }

    /**
     * If the call to the local engine to validate the policy returns an error, return (propagate) a
     * 400 error.
     */
    public void testPostPromote400_engineValidationFailed() {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(400);

        // Mock request
        RestRequest request = this.mockValidRequest();
        when(this.engine.promote(any(JsonNode.class))).thenReturn(expectedResponse);

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());
    }

    /**
     * If the promotion succeeds, return a 200 response.
     *
     * <p>Covered test cases (after promotion):
     *
     * <ul>
     *   <li>Target space hash is regenerated.
     *   <li>Elements marked for promotion, under the "add" and "update" operations, exist in the
     *       target space.
     *   <li>Elements marked for promotion, under the "delete" operation, no longer exist in the
     *       target space.
     *   <li>A 200 OK response is returned.
     * </ul>
     */
    public void testPostPromote200_success() {
        fail("Not yet implemented");
    }
}
