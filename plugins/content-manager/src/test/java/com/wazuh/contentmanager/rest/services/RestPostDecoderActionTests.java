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

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.Before;

import java.io.IOException;
import java.util.Map;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import org.mockito.ArgumentCaptor;

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

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.service = mock(EngineService.class);
        this.action = new RestPostDecoderAction(this.service);
    }

    /**
     * Test the {@link RestPostDecoderAction#handleRequest(decoder)} method when the request is
     * complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException
     */
    public void testPostDecoder200() throws IOException {
        // Mock
        RestRequest request = buildRequest(DECODER_PAYLOAD, null);
        RestResponse engineResponse = new RestResponse("Decoder created", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(engineResponse, actualResponse);
        assertEquals(RestStatus.OK, bytesRestResponse.status());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validate(payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        assertEquals("decoder", captured.get("type").asText());
        assertFalse(captured.has("integration"));
        JsonNode resource = captured.get("resource");
        assertTrue(resource.hasNonNull("id"));
        UUID.fromString(resource.get("id").asText());
    }

    /**
     * Test the {@link RestPostDecoderAction#handleRequest(decoder)} method when the decoder has not
     * been created (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testPostDecoder400() throws IOException {
        // Mock
        RestRequest request = buildRequest(DECODER_PAYLOAD_WITH_ID, null);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse expectedResponse =
                new RestResponse(
                        "Resource ID must not be provided on create.",
                        RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /**
     * Test missing integration field returns 400.
     *
     * @throws IOException
     */
    public void testPostDecoderMissingIntegration400() throws IOException {
        RestRequest request =
                buildRequest(
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
                                + "}",
                        null);

        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        RestResponse expectedResponse =
                new RestResponse(
                        "Integration ID is required.",
                        RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
        verify(this.service, never()).validate(any(JsonNode.class));
    }

    /**
     * Test the {@link RestPostDecoderAction#handleRequest(RestRequest)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostDecoder500() throws IOException {
        // Mock
        this.action = new RestPostDecoderAction(null);
        RestRequest request = buildRequest(DECODER_PAYLOAD, null);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse expectedResponse =
                new RestResponse(
                        "Engine service unavailable.",
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, bytesRestResponse.status());
    }

    private RestRequest buildRequest(String payload, String decoderId) {
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withContent(new BytesArray(payload), XContentType.JSON);
        if (decoderId != null) {
            builder.withParams(
                    Map.of(
                            "id",
                            decoderId,
                            "decoder_id",
                            decoderId));
        }
        return builder.build();
    }

    private RestResponse parseResponse(BytesRestResponse response) {
        JsonNode node = FixtureFactory.from(response.content().utf8ToString());
        return new RestResponse(node.get("message").asText(), node.get("status").asInt());
    }
}
