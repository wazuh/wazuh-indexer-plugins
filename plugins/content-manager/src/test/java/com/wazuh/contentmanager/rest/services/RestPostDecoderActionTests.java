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
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Before;
import org.junit.BeforeClass;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
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
 * Unit tests for the {@link RestPostDecoderAction} class. This test suite validates the REST API
 * endpoint responsible for creating new CTI Decoders.
 *
 * <p>Tests verify Decoder creation requests, proper handling of Decoder data, and appropriate HTTP
 * response codes for successful Decoder creation and validation errors.
 */
public class RestPostDecoderActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPostDecoderAction action;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final String DECODER_PAYLOAD =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"description\": \"Example decoder description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String DECODER_PAYLOAD_WITH_ID =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"integration\": \"integration-1\","
                    + "\"resource\": {"
                    + "  \"id\": \"82e215c4-988a-4f64-8d15-b98b2fc03a4f\","
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"description\": \"Example decoder description\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String DECODER_PAYLOAD_MISSING_INTEGRATION =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"resource\": {"
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"description\": \"Example decoder description\","
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
            // Already initialized, ignore
        }
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.service = mock(EngineService.class);
        this.action = new RestPostDecoderAction(this.service);
    }

    /**
     * Test successful decoder creation returns 202 Accepted.
     *
     * @throws Exception When an error occurs
     */
    public void testPostDecoderSuccess() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientForIndex();

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, client);

        // Assert
        assertEquals(RestStatus.CREATED.getStatus(), actualResponse.getStatus());

        assertTrue(actualResponse.getMessage().startsWith("Decoder created successfully with ID:"));

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validate(payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        assertEquals("decoder", captured.get("type").asText());
        assertFalse(captured.has("integration"));

        JsonNode resource = captured.get("resource");
        assertTrue(resource.hasNonNull("id"));

        // Verify timestamps were added
        assertTrue(resource.has("metadata"));
        JsonNode metadata = resource.get("metadata");
        assertTrue(metadata.has("author"));
        JsonNode author = metadata.get("author");
        assertTrue(author.has("date"));
        assertTrue(author.has("modified"));
        assertNotNull(author.get("date").asText());
        assertNotNull(author.get("modified").asText());
    }

    /** Test that providing a resource ID on creation returns 400 Bad Request. */
    public void testPostDecoderWithIdReturns400() {
        // Arrange
        RestRequest request = this.buildRequest(DECODER_PAYLOAD_WITH_ID);

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, null);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());

        RestResponse expectedResponse =
                new RestResponse(
                        "Resource ID must not be provided on create.", RestStatus.BAD_REQUEST.getStatus());
        assertEquals(expectedResponse, actualResponse);
        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing integration field returns 400 Bad Request. */
    public void testPostDecoderMissingIntegrationReturns400() {
        // Arrange
        RestRequest request = this.buildRequest(DECODER_PAYLOAD_MISSING_INTEGRATION);

        // Act
        RestResponse response = this.action.handleRequest(request, null);
        RestResponse actualResponse = response;

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());

        RestResponse expectedResponse =
                new RestResponse("Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
        assertEquals(expectedResponse, actualResponse);
        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that null engine service returns 500 Internal Server Error. */
    public void testPostDecoderEngineUnavailableReturns500() {
        // Arrange
        this.action = new RestPostDecoderAction(null);
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, null);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), actualResponse.getStatus());

        RestResponse expectedResponse =
                new RestResponse(
                        "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        assertEquals(expectedResponse, actualResponse);
    }

    /** Test that missing request body returns 400 Bad Request. */
    public void testPostDecoderMissingBodyReturns400() {
        // Arrange
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, null);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());

        RestResponse expectedResponse =
                new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());

        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Test that missing integration returns 400 Bad Request.
     *
     * @throws Exception When an error occurs
     */
    public void testPostDecoderIntegrationNotFoundReturns400() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientWithMissingIntegration();

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());

        assertTrue(actualResponse.getMessage().contains("Integration [integration-1] not found"));
    }

    /**
     * Test that integration without document field returns 400 Bad Request.
     *
     * @throws Exception When an error occurs
     */
    public void testPostDecoderIntegrationWithoutDocumentReturns400() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientWithIntegrationWithoutDocument();

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        assertTrue(
                actualResponse
                        .getMessage()
                        .contains("Integration [integration-1] does not have space information."));
    }

    /**
     * Test that integration with invalid document returns 400 Bad Request.
     *
     * @throws Exception When an error occurs
     */
    public void testPostDecoderIntegrationInvalidDocumentReturns400() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientWithIntegrationInvalidDocument();

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        assertTrue(
                actualResponse
                        .getMessage()
                        .contains("Integration [integration-1] does not have space information."));
    }

    /**
     * Test that creating a decoder for an integration not in draft space returns 400 Bad Request.
     *
     * @throws Exception When an error occurs
     */
    public void testPostDecoderIntegrationNotInDraftSpaceReturns400() throws Exception {
        // Arrange
        RestRequest request = this.buildRequest(DECODER_PAYLOAD);
        Client client = this.buildClientWithIntegrationNotInDraftSpace();

        // Act
        RestResponse actualResponse = this.action.handleRequest(request, client);

        // Assert
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), actualResponse.getStatus());
        assertTrue(actualResponse.getMessage().contains("is not in draft space"));
    }

    private RestRequest buildRequest(String payload) {
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(payload), XContentType.JSON);
        return builder.build();
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
        document.put("decoders", new ArrayList<>());
        // Use mutable map since updateIntegrationWithDecoder modifies it
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
        // Source with document field but not a Map
        Map<String, Object> source = new HashMap<>();
        source.put("document", "invalid-document-type");
        when(getResponse.getSourceAsMap()).thenReturn(source);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }

    private Client buildClientWithIntegrationNotInDraftSpace() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> document = new HashMap<>();
        document.put("decoders", new ArrayList<>());
        Map<String, Object> source = new HashMap<>();
        source.put("document", document);
        // Integration is in standard space, not draft
        Map<String, Object> space = new HashMap<>();
        space.put("name", "standard");
        source.put("space", space);
        when(getResponse.getSourceAsMap()).thenReturn(source);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(getResponse);

        return client;
    }
}
