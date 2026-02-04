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

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.BeforeClass;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

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
            "{" + "\"type\": \"decoder\"" + "}";

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

    /**
     * Test successful decoder update returns 200 OK.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutDecoderSuccess() throws Exception {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD, decoderId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientForIndex();
        this.action.setDecoderIndex(this.buildMockDecoderIndex(client));

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.OK, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().startsWith("Decoder updated successfully with ID:"));

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validate(payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        assertEquals("decoder", captured.get("type").asText());
        assertFalse(captured.has("integration"));

        JsonNode resource = captured.get("resource");
        assertEquals("82e215c4-988a-4f64-8d15-b98b2fc03a4f", resource.get("id").asText());

        // Verify metadata was preserved and modified timestamp was added
        assertTrue(resource.has("metadata"));
        JsonNode metadata = resource.get("metadata");
        assertTrue(metadata.has("author"));
        JsonNode author = metadata.get("author");
        assertTrue(author.has("modified"));
        assertNotNull(author.get("modified").asText());
        // Verify date was preserved
        assertTrue(author.has("date"));
        assertEquals("2026-01-01T00:00:00.000Z", author.get("date").asText());
    }

    /** Test that missing decoder ID returns 400 Bad Request. */
    public void testPutDecoderMissingIdReturns400() {
        // Arrange
        RestRequest request = this.buildRequest(DECODER_PAYLOAD, null);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("Decoder ID is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing request body returns 400 Bad Request. */
    public void testPutDecoderMissingBodyReturns400() {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", decoderId))
                        .build();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that missing resource field returns 400 Bad Request. */
    public void testPutDecoderMissingResourceReturns400() {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD_MISSING_RESOURCE, decoderId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /** Test that decoder ID mismatch returns 400 Bad Request. */
    public void testPutDecoderIdMismatchReturns400() {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD_WITH_ID_MISMATCH, decoderId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        "Decoder ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /**
     * Test that decoder not found returns 404 Not Found.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutDecoderNotFoundReturns404() throws Exception {
        // Arrange
        String decoderId = "d_non-existent-12345";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD, decoderId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientWithNonExistentDecoder();

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertTrue(actualResponse.getMessage().contains("Decoder [" + decoderId + "] not found"));
    }

    /** Test that null engine service returns 500 Internal Server Error. */
    public void testPutDecoderEngineUnavailableReturns500() {
        // Arrange
        this.action = new RestPutDecoderAction(null);
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        RestRequest request = this.buildRequest(DECODER_PAYLOAD, decoderId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Test that integration field in PUT request returns 400 Bad Request. */
    public void testPutDecoderWithIntegrationReturns400() {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        String payloadWithIntegration =
                "{"
                        + "\"type\": \"decoder\","
                        + "\"integration\": \"integration-1\","
                        + "\"resource\": {"
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
        RestRequest request = this.buildRequest(payloadWithIntegration, decoderId);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, null).toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());

        RestResponse expectedResponse =
                new RestResponse(
                        "Integration field is not allowed in PUT requests.",
                        RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = this.parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);

        verify(this.service, never()).validate(any(JsonNode.class));
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

        // Mock ContentIndex.exists() - decoder exists (for setFetchSource(false))
        GetResponse existsResponse = mock(GetResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
                .thenReturn(existsResponse);

        // Mock ContentIndex.getDocument() - decoder exists with metadata
        GetResponse getDocumentResponse = mock(GetResponse.class);
        when(getDocumentResponse.isExists()).thenReturn(true);
        String existingDocumentJson = "{"
                + "\"document\": {"
                + "  \"id\": \"82e215c4-988a-4f64-8d15-b98b2fc03a4f\","
                + "  \"name\": \"decoder/example/0\","
                + "  \"enabled\": true,"
                + "  \"metadata\": {"
                + "    \"title\": \"Example decoder\","
                + "    \"description\": \"Example decoder description\","
                + "    \"author\": {"
                + "      \"name\": \"Wazuh\","
                + "      \"date\": \"2026-01-01T00:00:00.000Z\","
                + "      \"modified\": \"2026-01-01T00:00:00.000Z\""
                + "    }"
                + "  }"
                + "},"
                + "\"space\": {"
                + "  \"name\": \"draft\""
                + "}"
                + "}";
        when(getDocumentResponse.getSourceAsString()).thenReturn(existingDocumentJson);
        // Mock getSourceAsMap for DocumentValidations.validateDocumentInSpace
        when(getDocumentResponse.getSourceAsMap()).thenReturn(Map.of("space", Map.of("name", "draft")));
        when(client.prepareGet(anyString(), anyString()).get())
                .thenReturn(getDocumentResponse);

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
        GetResponse existsResponse = mock(GetResponse.class);
        when(existsResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).setFetchSource(false).get())
                .thenReturn(existsResponse);

        // Mock validateDecoderSpace - decoder does not exist
        GetResponse spaceResponse = mock(GetResponse.class);
        when(spaceResponse.isExists()).thenReturn(false);
        when(client.prepareGet(anyString(), anyString()).get()).thenReturn(spaceResponse);

        return client;
    }

    /**
     * Test that metadata.author.date is preserved while other metadata fields can be updated.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutDecoderPreservesOnlyDateAndUpdatesOtherMetadata() throws Exception {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        String updatePayload = "{"
                + "\"type\": \"decoder\","
                + "\"resource\": {"
                + "  \"name\": \"decoder/example/0\","
                + "  \"enabled\": false,"
                + "  \"metadata\": {"
                + "    \"title\": \"UPDATED Title\","
                + "    \"description\": \"UPDATED Description\","
                + "    \"author\": {"
                + "      \"name\": \"UPDATED Author\""
                + "    }"
                + "  }"
                + "}"
                + "}";
        RestRequest request = this.buildRequest(updatePayload, decoderId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientForIndex();
        ContentIndex mockDecoderIndex = this.buildMockDecoderIndex(client);
        this.action.setDecoderIndex(mockDecoderIndex);

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        assertEquals(RestStatus.OK, bytesRestResponse.status());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validate(payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        JsonNode resource = captured.get("resource");
        JsonNode metadata = resource.get("metadata");

        assertEquals("UPDATED Title", metadata.get("title").asText());
        assertEquals("UPDATED Description", metadata.get("description").asText());
        assertEquals("UPDATED Author", metadata.get("author").get("name").asText());
        assertEquals("2026-01-01T00:00:00.000Z", metadata.get("author").get("date").asText());

        assertTrue(metadata.get("author").has("modified"));
        String modified = metadata.get("author").get("modified").asText();
        assertNotNull(modified);
        assertFalse(modified.equals("2026-01-01T00:00:00.000Z"));

        // Verify the decoder index was used to create the document
        ArgumentCaptor<JsonNode> indexCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(mockDecoderIndex).create(anyString(), indexCaptor.capture());
        JsonNode indexedDoc = indexCaptor.getValue();
        JsonNode indexedResource = indexedDoc.get("document");
        JsonNode indexedMetadata = indexedResource.get("metadata");

        assertEquals("UPDATED Title", indexedMetadata.get("title").asText());
        assertEquals("UPDATED Description", indexedMetadata.get("description").asText());
        assertEquals("UPDATED Author", indexedMetadata.get("author").get("name").asText());
        assertEquals("2026-01-01T00:00:00.000Z", indexedMetadata.get("author").get("date").asText());
    }

    /**
     * Test that metadata.author.date is preserved even when no metadata is provided in request.
     *
     * @throws Exception When an error occurs during test execution.
     */
    public void testPutDecoderPreservesDateWhenNoMetadataInRequest() throws Exception {
        // Arrange
        String decoderId = "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f";
        String updatePayload = "{"
                + "\"type\": \"decoder\","
                + "\"resource\": {"
                + "  \"name\": \"decoder/example/0\","
                + "  \"enabled\": false"
                + "}"
                + "}";
        RestRequest request = this.buildRequest(updatePayload, decoderId);
        RestResponse engineResponse = new RestResponse("Validation passed", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = this.buildClientForIndex();
        this.action.setDecoderIndex(this.buildMockDecoderIndex(client));

        // Act
        BytesRestResponse bytesRestResponse =
                this.action.handleRequest(request, client).toBytesRestResponse();

        assertEquals(RestStatus.OK, bytesRestResponse.status());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validate(payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        JsonNode resource = captured.get("resource");
        JsonNode metadata = resource.get("metadata");

        assertEquals("Example decoder", metadata.get("title").asText());
        assertEquals("Example decoder description", metadata.get("description").asText());
        assertEquals("Wazuh", metadata.get("author").get("name").asText());
        assertEquals("2026-01-01T00:00:00.000Z", metadata.get("author").get("date").asText());

        assertTrue(metadata.get("author").has("modified"));
        String modified = metadata.get("author").get("modified").asText();
        assertNotNull(modified);
        assertFalse(modified.equals("2026-01-01T00:00:00.000Z"));
    }

    private ContentIndex buildMockDecoderIndex(Client client) throws IOException {
        ContentIndex mockIndex = mock(ContentIndex.class);
        when(mockIndex.exists(anyString())).thenReturn(true);

        String existingDocumentJson = "{"
                + "\"document\": {"
                + "  \"id\": \"82e215c4-988a-4f64-8d15-b98b2fc03a4f\","
                + "  \"name\": \"decoder/example/0\","
                + "  \"enabled\": true,"
                + "  \"metadata\": {"
                + "    \"title\": \"Example decoder\","
                + "    \"description\": \"Example decoder description\","
                + "    \"author\": {"
                + "      \"name\": \"Wazuh\","
                + "      \"date\": \"2026-01-01T00:00:00.000Z\","
                + "      \"modified\": \"2026-01-01T00:00:00.000Z\""
                + "    }"
                + "  }"
                + "},"
                + "\"space\": {"
                + "  \"name\": \"draft\""
                + "}"
                + "}";
        ObjectMapper mapper = new ObjectMapper();
        JsonNode documentNode = mapper.readTree(existingDocumentJson);
        when(mockIndex.getDocument(anyString())).thenReturn(documentNode);

        return mockIndex;
    }
}
