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

import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestPostKvdbAction} class. This test suite validates the REST API
 * endpoint responsible for creating new CTI Kvdbs.
 *
 * <p>Tests verify Kvdb creation requests, proper handling of Kvdb data, and appropriate HTTP
 * response codes for successful Kvdb creation and validation errors.
 */
public class RestPostKvdbActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPostKvdbAction action;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final String KVDB_PAYLOAD =
            "{"
                    + "\"type\": \"kvdb\","
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example KVDB\","
                    + "    \"description\": \"Example KVDB description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String KVDB_PAYLOAD_WITH_ID =
            "{"
                    + "\"type\": \"kvdb\","
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"id\": \"82e215c4-988a-4f64-8d15-b98b2fc03a4f\","
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example KVDB\","
                    + "    \"description\": \"Example KVDB description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String KVDB_PAYLOAD_MISSING_INTEGRATION =
            "{"
                    + "\"type\": \"kvdb\","
                    + "\"resource\": {"
                    + "  \"name\": \"kvdb/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example KVDB\","
                    + "    \"description\": \"Example KVDB description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    /** Initialize PluginSettings singleton once for all tests. */
    @BeforeClass
    public static void setUpClass() {
        // Initialize PluginSettings singleton - it will persist across all tests
        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
        }
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.service = mock(EngineService.class);
        this.action = new RestPostKvdbAction(this.service);
    }

    /** Test successful KVDB creation returns 201 Created and updates integration. */
    public void testPostKvdbSuccess() throws Exception {
        // Arrange
        RestRequest request = buildRequest(KVDB_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = buildClientForIndex();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert - Verify response status and message
        assertEquals(RestStatus.CREATED, bytesRestResponse.status());

        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().startsWith("KVDB created successfully with ID:"));

        // Extract the returned ID from response message
        String returnedId =
                actualResponse.getMessage().substring("KVDB created successfully with ID: ".length());
        // Verify response returns ID WITH prefix
        assertTrue(returnedId.startsWith("d_"));

        // Verify engine validation was called with correct payload
        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validate(payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        assertEquals("kvdb", captured.get("type").asText());
        assertFalse(captured.has("integration"));

        JsonNode resource = captured.get("resource");
        assertTrue(resource.hasNonNull("id"));
        String engineKvdbId = resource.get("id").asText();
        // Validate engine receives UUID WITHOUT prefix
        assertFalse(engineKvdbId.startsWith("d_"));
        UUID.fromString(engineKvdbId); // Validate it's a valid UUID

        // Verify timestamps were added
        assertTrue(resource.has("metadata"));
        JsonNode metadata = resource.get("metadata");
        assertTrue(metadata.has("date"));
        assertTrue(metadata.has("modified"));
        assertNotNull(metadata.get("date").asText());
        assertNotNull(metadata.get("modified").asText());

        // Verify client.index() was called twice: once for KVDB, once for integration update
        ArgumentCaptor<IndexRequest> indexRequestCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(client, org.mockito.Mockito.times(2)).index(indexRequestCaptor.capture());

        java.util.List<IndexRequest> indexRequests = indexRequestCaptor.getAllValues();
        assertEquals(2, indexRequests.size());

        // First call should be for creating the KVDB
        IndexRequest kvdbIndexRequest = indexRequests.get(0);
        assertTrue(kvdbIndexRequest.index().contains("kvdb"));

        // Second call should be for updating the integration
        IndexRequest integrationUpdateRequest = indexRequests.get(1);
        assertEquals(".cti-integrations", integrationUpdateRequest.index());
        assertEquals("integration-1", integrationUpdateRequest.id());

        // Verify the integration was updated with the KVDB ID
        Map<String, Object> integrationSource = integrationUpdateRequest.sourceAsMap();
        assertNotNull(integrationSource);
        assertTrue(integrationSource.containsKey("document"));

        @SuppressWarnings("unchecked")
        Map<String, Object> document = (Map<String, Object>) integrationSource.get("document");
        assertNotNull(document);
        assertTrue(document.containsKey("kvdbs"));

        @SuppressWarnings("unchecked")
        java.util.List<String> kvdbs = (java.util.List<String>) document.get("kvdbs");
        assertNotNull(kvdbs);
        assertEquals(1, kvdbs.size());
        String integrationKvdbId = kvdbs.get(0);
        // Verify integration receives ID WITHOUT prefix
        assertFalse(integrationKvdbId.startsWith("d_"));
        assertEquals(engineKvdbId, integrationKvdbId); // Should match engine ID
    }

    /** Test that providing a resource ID on creation returns 400 Bad Request. */
    public void testPostKvdbWithIdReturns400() throws IOException {
        // Arrange
        RestRequest request = buildRequest(KVDB_PAYLOAD_WITH_ID, null);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        "Resource ID must not be provided on create.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing integration field returns 400 Bad Request. */
    public void testPostKvdbMissingIntegrationReturns400() throws IOException {
        // Arrange
        RestRequest request = buildRequest(KVDB_PAYLOAD_MISSING_INTEGRATION, null);

        // Act
        RestResponse response = this.action.handleRequest(request, null);
        BytesRestResponse bytesRestResponse = response.toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that null engine service returns 500 Internal Server Error. */
    public void testPostKvdbEngineUnavailableReturns500() throws IOException {
        // Arrange
        this.action = new RestPostKvdbAction(null);
        RestRequest request = buildRequest(KVDB_PAYLOAD, null);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Test that missing request body returns 400 Bad Request. */
    public void testPostKvdbMissingBodyReturns400() throws IOException {
        // Arrange
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Test that missing integration returns 400 Bad Request. */
    public void testPostKvdbIntegrationNotFoundReturns400() throws Exception {
        // Arrange
        RestRequest request = buildRequest(KVDB_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = buildClientWithMissingIntegration();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().contains("Integration [integration-1] not found"));
    }

    /** Test that integration without space field returns 400 Bad Request. */
    public void testPostKvdbIntegrationWithoutDocumentReturns400() throws Exception {
        // Arrange
        RestRequest request = buildRequest(KVDB_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = buildClientWithIntegrationWithoutDocument();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertTrue(
                actualResponse
                        .getMessage()
                        .contains("Integration [integration-1] does not have space information."));
    }

    /** Test that integration with invalid space returns 400 Bad Request. */
    public void testPostKvdbIntegrationInvalidDocumentReturns400() throws Exception {
        // Arrange
        RestRequest request = buildRequest(KVDB_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = buildClientWithIntegrationInvalidDocument();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertTrue(
                actualResponse
                        .getMessage()
                        .contains("Integration [integration-1] has invalid space information."));
    }

    private RestRequest buildRequest(String payload, String kvdbId) {
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(payload), XContentType.JSON);
        if (kvdbId != null) {
            builder.withParams(Map.of("id", kvdbId, "kvdb_id", kvdbId));
        }
        return builder.build();
    }

    private RestResponse parseResponse(BytesRestResponse response) {
        JsonNode node = FixtureFactory.from(response.content().utf8ToString());
        return new RestResponse(node.get("message").asText(), node.get("status").asInt());
    }

    private Client buildClientForIndex() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> document = new HashMap<>();
        document.put("kvdbs", new ArrayList<>());
        // Use mutable map since updateIntegrationWithKvdb modifies it
        Map<String, Object> source = new HashMap<>();
        source.put("document", document);
        // Add space information - integration is in draft space
        Map<String, Object> space = new HashMap<>();
        space.put("name", "draft");
        source.put("space", space);
        when(getResponse.getSourceAsMap()).thenReturn(source);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }

    private Client buildClientWithMissingIntegration() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }

    private Client buildClientWithIntegrationWithoutDocument() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        // Source without document field
        Map<String, Object> source = new HashMap<>();
        when(getResponse.getSourceAsMap()).thenReturn(source);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }

    private Client buildClientWithIntegrationInvalidDocument() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        // Source with space field but not a Map (invalid type)
        Map<String, Object> source = new HashMap<>();
        source.put("space", "invalid-space-type");
        when(getResponse.getSourceAsMap()).thenReturn(source);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }
}
