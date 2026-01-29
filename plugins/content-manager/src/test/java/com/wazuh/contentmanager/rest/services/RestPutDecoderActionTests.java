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
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.services.FixtureFactory;
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
 * Unit tests for the {@link RestPutDecoderAction} class. This test suite validates the REST API
 * endpoint responsible for updating new CTI Decoders.
 *
 * <p>Tests verify Decoder update requests, proper handling of Decoder data, and appropriate HTTP
 * response codes for successful Decoder update errors.
 */
public class RestPutDecoderActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestPutDecoderAction action;
    private static final String DECODER_PAYLOAD =
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

    private static final String DECODER_PAYLOAD_WITH_ID_MISMATCH =
            "{"
                    + "\"type\": \"decoder\","
                    + "\"resource\": {"
                    + "  \"id\": \"different-uuid-12345\","
                    + "  \"name\": \"decoder/example/0\","
                    + "  \"enabled\": true,"
                    + "  \"metadata\": {"
                    + "    \"title\": \"Example decoder\","
                    + "    \"author\": {"
                    + "      \"name\": \"Wazuh\""
                    + "    }"
                    + "  }"
                    + "}"
                    + "}";

    private static final String DECODER_PAYLOAD_MISSING_RESOURCE =
            "{"
                    + "\"type\": \"decoder\""
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
        this.action = new RestPutDecoderAction(this.service);
    }

    /** Test successful decoder update returns 200 OK. */
    public void testPutDecoderSuccess() throws Exception {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = buildRequest(DECODER_PAYLOAD, decoderId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = buildClientForIndex();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.OK, bytesRestResponse.status());

        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().startsWith("Decoder updated successfully with ID:"));

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validate(payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        assertEquals("decoder", captured.get("type").asText());
        assertFalse(captured.has("integration"));

        JsonNode resource = captured.get("resource");
        assertEquals("82e215c4-988a-4f64-8d15-b98b2fc03a4f", resource.get("id").asText());
    }

    /** Test that missing decoder ID returns 400 Bad Request. */
    public void testPutDecoderMissingIdReturns400() throws IOException {
        // Arrange
        RestRequest request = buildRequest(DECODER_PAYLOAD, null);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("Decoder ID is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing request body returns 400 Bad Request. */
    public void testPutDecoderMissingBodyReturns400() throws IOException {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withParams(Map.of("id", decoderId))
                .build();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing resource field returns 400 Bad Request. */
    public void testPutDecoderMissingResourceReturns400() throws IOException {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = buildRequest(DECODER_PAYLOAD_MISSING_RESOURCE, decoderId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that decoder ID mismatch returns 400 Bad Request. */
    public void testPutDecoderIdMismatchReturns400() throws IOException {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = buildRequest(DECODER_PAYLOAD_WITH_ID_MISMATCH, decoderId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("Decoder ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that decoder not found returns 404 Not Found. */
    public void testPutDecoderNotFoundReturns404() throws Exception {
        // Arrange
        String decoderId = "d_non-existent-12345";
        RestRequest request = buildRequest(DECODER_PAYLOAD, decoderId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = buildClientWithNonExistentDecoder();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().contains("Decoder [" + decoderId + "] not found"));
    }

    /** Test that null engine service returns 500 Internal Server Error. */
    public void testPutDecoderEngineUnavailableReturns500() throws IOException {
        // Arrange
        this.action = new RestPutDecoderAction(null);
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = buildRequest(DECODER_PAYLOAD, decoderId);

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

    private RestRequest buildRequest(String payload, String decoderId) {
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(payload), XContentType.JSON);
        if (decoderId != null) {
            builder.withParams(Map.of("id", decoderId, "decoder_id", decoderId));
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

        // Mock ContentIndex.exists() - decoder exists
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get()).thenReturn(getResponse);

        return client;
    }

    private Client buildClientWithNonExistentDecoder() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);

        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any(TimeUnit.class))).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);

        // Mock ContentIndex.exists() - decoder does not exist
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get()).thenReturn(getResponse);

        return client;
    }
}
