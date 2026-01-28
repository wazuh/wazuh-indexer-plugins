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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;

import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.model.SpaceDiff;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
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
    private ObjectMapper objectMapper;

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
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Test the {@link RestPostPromoteAction#handleRequest(RestRequest)} method when the request is
     * complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostPromote200() throws IOException {
        // Arrange
        SpaceDiff spaceDiff = this.createValidSpaceDiff();
        String requestJson = this.objectMapper.writeValueAsString(spaceDiff);

        // Mock policy document for target space (test)
        Map<String, Object> policyDoc = new HashMap<>();
        Map<String, Object> docContent = new HashMap<>();
        docContent.put("name", "test-policy");
        policyDoc.put("document", docContent);
        when(this.spaceService.getPolicy("test")).thenReturn(policyDoc);

        // Mock decoder document in source space (draft)
        Map<String, Object> decoderDoc = new HashMap<>();
        Map<String, Object> decoderContent = new HashMap<>();
        decoderContent.put("name", "test-decoder");
        decoderDoc.put("document", decoderContent);
        Map<String, String> decoderSpace = new HashMap<>();
        decoderSpace.put("name", "draft");
        decoderDoc.put("space", decoderSpace);
        when(this.spaceService.getDocument(anyString(), eq("decoder-123")))
                .thenReturn(decoderDoc);

        // Mock index names
        when(this.spaceService.getIndexForResourceType("decoders"))
                .thenReturn(".cti-decoders");
        when(this.spaceService.getIndexForResourceType("integrations"))
                .thenReturn(".cti-integrations");
        when(this.spaceService.getIndexForResourceType("kvdbs")).thenReturn(".cti-kvdbs");
        when(this.spaceService.getIndexForResourceType("filters"))
                .thenReturn(".engine-filters");

        // Mock target space resources (empty for simplicity)
        when(this.spaceService.getResourcesBySpace(anyString(), eq("test")))
                .thenReturn(new HashMap<>());

        // Mock buildEnginePayload to return a valid JsonNode
        ObjectNode mockEnginePayload = this.objectMapper.createObjectNode();
        mockEnginePayload.put("policy", "test-policy");
        when(this.spaceService.buildEnginePayload(
                        any(), anyString(), anyMap(), anyMap(), anyMap(), anyMap(), any(), any(), any(), any()))
                .thenReturn(mockEnginePayload);

        // Mock engine validation success
        RestResponse engineResponse = new RestResponse("Validation successful", 200);
        when(this.engine.promote(any(JsonNode.class))).thenReturn(engineResponse);

        // Create mock request
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content())
                .thenReturn(new BytesArray(requestJson.getBytes(StandardCharsets.UTF_8)));

        // Act
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("Promotion completed successfully"));
        verify(this.spaceService).consolidateAddUpdateResources(anyString(), anyMap(), eq("test"));
    }

    /**
     * Test the {@link RestPostPromoteAction#handleRequest(RestRequest)} method when validation fails.
     * The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostPromote400_InvalidSpace() throws IOException {
        // Arrange - Create a space diff with non-promotable space
        SpaceDiff spaceDiff = new SpaceDiff();
        spaceDiff.setSpace(Space.CUSTOM); // CUSTOM cannot be promoted
        SpaceDiff.Changes changes = new SpaceDiff.Changes();
        changes.setPolicy(List.of());
        changes.setIntegrations(List.of());
        changes.setKvdbs(List.of());
        changes.setDecoders(List.of());
        changes.setFilters(List.of());
        spaceDiff.setChanges(changes);

        String requestJson = this.objectMapper.writeValueAsString(spaceDiff);

        // Act
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content())
                .thenReturn(new BytesArray(requestJson.getBytes(StandardCharsets.UTF_8)));
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("cannot be promoted"));
    }

    /**
     * Test when only UPDATE operation is allowed for policy.
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostPromote400_InvalidPolicyOperation() throws IOException {
        // Arrange
        SpaceDiff spaceDiff = createValidSpaceDiff();
        SpaceDiff.OperationItem invalidPolicyOp = new SpaceDiff.OperationItem();
        invalidPolicyOp.setOperation(SpaceDiff.Operation.ADD);
        invalidPolicyOp.setId("policy");
        spaceDiff.getChanges().setPolicy(List.of(invalidPolicyOp));

        String requestJson = this.objectMapper.writeValueAsString(spaceDiff);

        // Act
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content())
                .thenReturn(new BytesArray(requestJson.getBytes(StandardCharsets.UTF_8)));
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(
                response.getMessage()
                        .contains("Only 'update' operation is supported for policy"));
    }

    /**
     * Test when a document stated in the payload is missing.
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostPromote400_MissingDocument() throws IOException {
        // Arrange
        SpaceDiff spaceDiff = createValidSpaceDiff();
        String requestJson = this.objectMapper.writeValueAsString(spaceDiff);

        // Mock policy exists in target space (test)
        Map<String, Object> policyDoc = new HashMap<>();
        policyDoc.put("document", new HashMap<>());
        when(this.spaceService.getPolicy("test")).thenReturn(policyDoc);

        // Mock index names for all resource types
        when(this.spaceService.getIndexForResourceType("decoders"))
                .thenReturn(".cti-decoders");
        when(this.spaceService.getIndexForResourceType("integrations"))
                .thenReturn(".cti-integrations");
        when(this.spaceService.getIndexForResourceType("kvdbs")).thenReturn(".cti-kvdbs");
        when(this.spaceService.getIndexForResourceType("filters"))
                .thenReturn(".engine-filters");

        // Mock decoder does not exist
        when(this.spaceService.getDocument(anyString(), eq("decoder-123"))).thenReturn(null);

        // Act
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content())
                .thenReturn(new BytesArray(requestJson.getBytes(StandardCharsets.UTF_8)));
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("Resource 'decoder-123' not found"));
    }

    /**
     * Test when engine validation fails.
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostPromote400_EngineValidationFailed() throws IOException {
        // Arrange
        SpaceDiff spaceDiff = this.createValidSpaceDiff();
        String requestJson = this.objectMapper.writeValueAsString(spaceDiff);

        // Mock policy document in target space (test)
        Map<String, Object> policyDoc = new HashMap<>();
        policyDoc.put("document", new HashMap<>());
        when(this.spaceService.getPolicy("test")).thenReturn(policyDoc);

        // Mock decoder document in source space (draft)
        Map<String, Object> decoderDoc = new HashMap<>();
        decoderDoc.put("document", new HashMap<>());
        Map<String, String> decoderSpace = new HashMap<>();
        decoderSpace.put("name", "draft");
        decoderDoc.put("space", decoderSpace);
        when(this.spaceService.getDocument(anyString(), eq("decoder-123")))
                .thenReturn(decoderDoc);
        when(this.spaceService.getIndexForResourceType("decoders"))
                .thenReturn(".cti-decoders");
        when(this.spaceService.getIndexForResourceType("integrations"))
                .thenReturn(".cti-integrations");
        when(this.spaceService.getIndexForResourceType("kvdbs")).thenReturn(".cti-kvdbs");
        when(this.spaceService.getIndexForResourceType("filters"))
                .thenReturn(".engine-filters");

        // Mock target space resources
        when(this.spaceService.getResourcesBySpace(anyString(), eq("test")))
                .thenReturn(new HashMap<>());

        // Mock buildEnginePayload to return a valid JsonNode
        ObjectNode mockEnginePayload = this.objectMapper.createObjectNode();
        mockEnginePayload.put("policy", "test-policy");
        when(this.spaceService.buildEnginePayload(
                        any(), anyString(), anyMap(), anyMap(), anyMap(), anyMap(), any(), any(), any(), any()))
                .thenReturn(mockEnginePayload);

        // Mock engine validation failure
        RestResponse engineResponse =
                new RestResponse("Validation failed: Invalid decoder syntax", 400);
        when(this.engine.promote(any(JsonNode.class))).thenReturn(engineResponse);

        // Act
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content())
                .thenReturn(new BytesArray(requestJson.getBytes(StandardCharsets.UTF_8)));
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(
                response.getMessage().contains("Validation failed: Invalid decoder syntax"));
    }

    /**
     * Test the {@link RestPostPromoteAction#handleRequest(RestRequest)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostPromote500() throws IOException {
        // Arrange
        SpaceDiff spaceDiff = this.createValidSpaceDiff();
        String requestJson = this.objectMapper.writeValueAsString(spaceDiff);

        // Mock policy document in target space (test)
        Map<String, Object> policyDoc = new HashMap<>();
        policyDoc.put("document", new HashMap<>());
        when(this.spaceService.getPolicy("test")).thenReturn(policyDoc);

        // Mock decoder document in source space (draft)
        Map<String, Object> decoderDoc = new HashMap<>();
        decoderDoc.put("document", new HashMap<>());
        Map<String, String> decoderSpace = new HashMap<>();
        decoderSpace.put("name", "draft");
        decoderDoc.put("space", decoderSpace);
        when(this.spaceService.getDocument(anyString(), eq("decoder-123")))
                .thenReturn(decoderDoc);
        when(this.spaceService.getIndexForResourceType("decoders"))
                .thenReturn(".cti-decoders");
        when(this.spaceService.getIndexForResourceType("integrations"))
                .thenReturn(".cti-integrations");
        when(this.spaceService.getIndexForResourceType("kvdbs")).thenReturn(".cti-kvdbs");
        when(this.spaceService.getIndexForResourceType("filters"))
                .thenReturn(".engine-filters");

        // Mock target space resources
        when(this.spaceService.getResourcesBySpace(anyString(), eq("test")))
                .thenReturn(new HashMap<>());

        // Mock buildEnginePayload to return a valid JsonNode
        ObjectNode mockEnginePayload = this.objectMapper.createObjectNode();
        mockEnginePayload.put("policy", "test-policy");
        when(this.spaceService.buildEnginePayload(
                        any(), anyString(), anyMap(), anyMap(), anyMap(), anyMap(), any(), any(), any(), any()))
                .thenReturn(mockEnginePayload);

        // Mock engine validation success
        RestResponse engineResponse = new RestResponse("Validation successful", 200);
        when(this.engine.promote(any(JsonNode.class))).thenReturn(engineResponse);

        // Mock consolidation failure
        doThrow(new IOException("Database connection error"))
                .when(this.spaceService)
                .consolidateAddUpdateResources(anyString(), anyMap(), anyString());

        // Act
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content())
                .thenReturn(new BytesArray(requestJson.getBytes(StandardCharsets.UTF_8)));
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("Database connection error"));
    }

    /**
     * Test when the engine is unreachable.
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostPromote500_EngineUnreachable() throws IOException {
        // Arrange
        SpaceDiff spaceDiff = this.createValidSpaceDiff();
        String requestJson = this.objectMapper.writeValueAsString(spaceDiff);

        // Mock policy document in target space (test)
        Map<String, Object> policyDoc = new HashMap<>();
        policyDoc.put("document", new HashMap<>());
        when(this.spaceService.getPolicy("test")).thenReturn(policyDoc);

        // Mock decoder document in source space (draft)
        Map<String, Object> decoderDoc = new HashMap<>();
        decoderDoc.put("document", new HashMap<>());
        Map<String, String> decoderSpace = new HashMap<>();
        decoderSpace.put("name", "draft");
        decoderDoc.put("space", decoderSpace);
        when(this.spaceService.getDocument(anyString(), eq("decoder-123")))
                .thenReturn(decoderDoc);
        when(this.spaceService.getIndexForResourceType("decoders"))
                .thenReturn(".cti-decoders");
        when(this.spaceService.getIndexForResourceType("integrations"))
                .thenReturn(".cti-integrations");
        when(this.spaceService.getIndexForResourceType("kvdbs")).thenReturn(".cti-kvdbs");
        when(this.spaceService.getIndexForResourceType("filters"))
                .thenReturn(".engine-filters");

        // Mock target space resources
        when(this.spaceService.getResourcesBySpace(anyString(), eq("test")))
                .thenReturn(new HashMap<>());

        // Mock buildEnginePayload to return a valid JsonNode
        ObjectNode mockEnginePayload = this.objectMapper.createObjectNode();
        mockEnginePayload.put("policy", "test-policy");
        when(this.spaceService.buildEnginePayload(
                        any(), anyString(), anyMap(), anyMap(), anyMap(), anyMap(), any(), any(), any(), any()))
                .thenReturn(mockEnginePayload);

        // Mock engine unreachable (returns 500)
        RestResponse engineResponse =
                new RestResponse("Engine service unavailable", 500);
        when(this.engine.promote(any(JsonNode.class))).thenReturn(engineResponse);

        // Act
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content())
                .thenReturn(new BytesArray(requestJson.getBytes(StandardCharsets.UTF_8)));
        RestResponse response = this.action.handleRequest(request);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("Engine service unavailable"));
    }

    /**
     * Helper method to create a valid SpaceDiff for testing.
     *
     * @return A valid SpaceDiff instance.
     */
    private SpaceDiff createValidSpaceDiff() {
        SpaceDiff spaceDiff = new SpaceDiff();
        spaceDiff.setSpace(Space.DRAFT);

        SpaceDiff.Changes changes = new SpaceDiff.Changes();

        // Policy with UPDATE operation
        SpaceDiff.OperationItem policyOp = new SpaceDiff.OperationItem();
        policyOp.setOperation(SpaceDiff.Operation.UPDATE);
        policyOp.setId("policy");
        changes.setPolicy(List.of(policyOp));

        // Decoder with ADD operation
        SpaceDiff.OperationItem decoderOp = new SpaceDiff.OperationItem();
        decoderOp.setOperation(SpaceDiff.Operation.ADD);
        decoderOp.setId("decoder-123");
        changes.setDecoders(List.of(decoderOp));

        // Empty arrays for other resource types
        changes.setIntegrations(List.of());
        changes.setKvdbs(List.of());
        changes.setFilters(List.of());

        spaceDiff.setChanges(changes);
        return spaceDiff;
    }
}
