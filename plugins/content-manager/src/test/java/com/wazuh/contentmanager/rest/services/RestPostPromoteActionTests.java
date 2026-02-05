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
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
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

        // Mock space service.
        when(this.spaceService.getIndexForResourceType(Constants.KEY_POLICY))
                .thenReturn(Constants.INDEX_POLICIES);
        when(this.spaceService.getIndexForResourceType(Constants.KEY_INTEGRATIONS))
                .thenReturn(Constants.INDEX_INTEGRATIONS);
        when(this.spaceService.getIndexForResourceType(Constants.KEY_KVDBS))
                .thenReturn(Constants.INDEX_KVDBS);
        when(this.spaceService.getIndexForResourceType(Constants.KEY_RULES))
                .thenReturn(Constants.INDEX_RULES);
        when(this.spaceService.getIndexForResourceType(Constants.KEY_DECODERS))
                .thenReturn(Constants.INDEX_DECODERS);
        when(this.spaceService.getIndexForResourceType(Constants.KEY_FILTERS))
                .thenReturn(Constants.INDEX_FILTERS);

        // Mock getPolicy to return a valid policy document for target space
        Map<String, Object> mockPolicyDoc = new HashMap<>();
        mockPolicyDoc.put(Constants.KEY_DOCUMENT, new HashMap<>());
        when(this.spaceService.getPolicy(anyString())).thenReturn(mockPolicyDoc);

        // Mock getDocument to return valid documents with proper space fields
        Map<String, Object> mockDocument = new HashMap<>();
        Map<String, String> mockSpace = new HashMap<>();
        mockSpace.put("name", Space.DRAFT.toString());
        mockDocument.put(Constants.KEY_SPACE, mockSpace);
        mockDocument.put(Constants.KEY_DOCUMENT, new HashMap<>());
        when(this.spaceService.getDocument(anyString(), anyString())).thenReturn(mockDocument);

        // Mock getResourcesBySpace to return empty maps (target space is empty)
        when(this.spaceService.getResourcesBySpace(anyString(), anyString()))
                .thenReturn(new HashMap<>());

        // Mock buildEnginePayload to return a valid JsonNode
        ObjectMapper mapper = new ObjectMapper();
        when(this.spaceService.buildEnginePayload(
                        any(), anyString(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(mapper.createObjectNode());

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
                        "rules": [],
                        "decoders": [{"operation": "add", "id": "12345"}],
                        "filters": []
                    }
                }
                """;
        // spotless:on
        return this.createRestRequest(payload);
    }

    /** If any of the catalog indices do not exist, return a 500 error. */
    public void testPostPromote500_indexNotFound() throws Exception {
        // Mock expected response
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(500);
        expectedResponse.setMessage("Index [.cti-decoders] not found.");

        // Mock request - contains decoder with id "12345"
        RestRequest request = this.mockValidRequest();

        // Override the default mock to throw an exception simulating index not found
        when(this.spaceService.getDocument(eq(Constants.INDEX_DECODERS), anyString()))
                .thenThrow(
                        new org.opensearch.index.IndexNotFoundException("Index [.cti-decoders] not found."));

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
                        "rules": [],
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
                        "rules": [],
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
        assertEquals(expectedResponse.getStatus(), actualResponse.getStatus());
        assertTrue(actualResponse.getMessage().contains("required"));

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
    @AwaitsFix(bugUrl = "")
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
                        "rules": [],
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
     * If any of the documents stated in the request is under a different space, return a 400 error.
     */
    public void testPostPromote400_documentInWrongSpace() {
        // Mock engine to return success (200 OK)
        RestResponse engineResponse = new RestResponse();
        engineResponse.setStatus(200);
        engineResponse.setMessage("OK");
        when(this.engine.promote(any(JsonNode.class))).thenReturn(engineResponse);

        // Mock request
        // spotless:off
        String payload = """
                {
                  "space": "test",
                  "changes": {
                    "policy": [{"operation": "update", "id": "policy"}],
                    "integrations": [{"operation": "remove", "id": "integration"}],
                    "kvdbs": [],
                    "rules": [],
                    "decoders": [{"operation": "add", "id": "decoder-1"}, {"operation": "remove", "id": "decoder-2"}],
                    "filters": []
                  }
                }
                """;
        // spotless:on
        RestRequest request = this.createRestRequest(payload);

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(400, actualResponse.getStatus());
        assertTrue(actualResponse.getMessage().contains("expected source space"));
    }

    /**
     * If the promotion succeeds, return a 200 response.
     *
     * <p>Covered test cases (after promotion):
     *
     * <ul>
     *   <li>A 200 OK response is returned.
     * </ul>
     *
     * TODO needs to be done in an integration test.
     *
     * <ul>
     *   <li>Target space hash is regenerated.
     *   <li>Elements marked for promotion, under the "add" and "update" operations, exist in the
     *       target space.
     *   <li>Elements marked for promotion, under the "delete" operation, no longer exist in the
     *       target space.
     * </ul>
     */
    public void testPostPromote200_success() throws IOException {
        // Mock engine to return success (200 OK)
        RestResponse engineResponse = new RestResponse();
        engineResponse.setStatus(200);
        engineResponse.setMessage("OK");
        when(this.engine.promote(any(JsonNode.class))).thenReturn(engineResponse);

        // Mock spaces
        Map<String, String> mockSpaceDraft = new HashMap<>();
        mockSpaceDraft.put("name", Space.DRAFT.toString());
        Map<String, String> mockSpaceTest = new HashMap<>();
        mockSpaceTest.put("name", Space.TEST.toString());

        // Mock policy document for UPDATE operation (policy exists in draft space)
        Map<String, Object> mockPolicy = new HashMap<>();
        mockPolicy.put(Constants.KEY_SPACE, mockSpaceDraft);
        Map<String, Object> mockPolicyDoc = new HashMap<>();
        mockPolicyDoc.put("id", "policy");
        mockPolicy.put(Constants.KEY_DOCUMENT, mockPolicyDoc);
        when(this.spaceService.getDocument(eq(Constants.INDEX_POLICIES), eq("policy")))
                .thenReturn(mockPolicy);
        when(this.spaceService.getPolicy(eq("draft"))).thenReturn(mockPolicy);

        // Mock integration for DELETE operation (integration exists in test space - target)
        Map<String, Object> mockIntegration = new HashMap<>();
        mockIntegration.put(Constants.KEY_SPACE, mockSpaceTest);
        Map<String, Object> mockIntegrationDoc = new HashMap<>();
        mockIntegrationDoc.put("id", "integration");
        mockIntegration.put(Constants.KEY_DOCUMENT, mockIntegrationDoc);
        when(this.spaceService.getDocument(eq(Constants.INDEX_INTEGRATIONS), eq("integration")))
                .thenReturn(mockIntegration);

        // Mock decoder-1 for ADD operation (decoder-1 exists in draft space, not in test)
        Map<String, Object> mockDecoder1 = new HashMap<>();
        mockDecoder1.put(Constants.KEY_SPACE, mockSpaceDraft);
        Map<String, Object> mockDecoder1Doc = new HashMap<>();
        mockDecoder1Doc.put("id", "decoder-1");
        mockDecoder1.put(Constants.KEY_DOCUMENT, mockDecoder1Doc);
        when(this.spaceService.getDocument(eq(Constants.INDEX_DECODERS), eq("decoder-1")))
                .thenReturn(mockDecoder1);

        // Mock decoder-2 for DELETE operation (decoder-2 exists in test space - target)
        Map<String, Object> mockDecoder2 = new HashMap<>();
        mockDecoder2.put(Constants.KEY_SPACE, mockSpaceTest);
        Map<String, Object> mockDecoder2Doc = new HashMap<>();
        mockDecoder2Doc.put("id", "decoder-2");
        mockDecoder2.put(Constants.KEY_DOCUMENT, mockDecoder2Doc);
        when(this.spaceService.getDocument(eq(Constants.INDEX_DECODERS), eq("decoder-2")))
                .thenReturn(mockDecoder2);

        // spotless:off
        String payload = """
                {
                  "space": "draft",
                  "changes": {
                    "policy": [{"operation": "update", "id": "policy"}],
                    "integrations": [{"operation": "remove", "id": "integration"}],
                    "kvdbs": [],
                    "rules": [],
                    "decoders": [{"operation": "add", "id": "decoder-1"}, {"operation": "remove", "id": "decoder-2"}],
                    "filters": []
                  }
                }
                """;
        // spotless:on
        RestRequest request = this.createRestRequest(payload);

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        // Invoke method to test
        RestResponse actualResponse = this.action.handleRequest(request);

        // Verify
        assertEquals(200, actualResponse.getStatus());
        assertEquals(Constants.S_200_PROMOTION_COMPLETED, actualResponse.getMessage());
    }
}
