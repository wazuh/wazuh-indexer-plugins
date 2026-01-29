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

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.action.ActionFuture;
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

import java.io.IOException;
import java.util.Map;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.ArgumentCaptor;

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
        this.action = new RestPutDecoderAction(this.service);
    }

    /**
     * Test the {@link RestPutDecoderAction#handleRequest(decoder)} method when the request is
     * complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException
     */
    public void testPutDecoder200() throws Exception {
        // Mock
        RestRequest request = buildRequest(DECODER_PAYLOAD, "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f");
        RestResponse engineResponse = new RestResponse("Decoder updated", RestStatus.OK.getStatus());
        when(this.service.validate(any(JsonNode.class))).thenReturn(engineResponse);
        Client client = buildClientForIndex();
        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, client);

        // Assert
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(engineResponse, actualResponse);
        assertEquals(RestStatus.OK, bytesRestResponse.status());

        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.service).validate(payloadCaptor.capture());
        JsonNode captured = payloadCaptor.getValue();
        assertEquals("decoder", captured.get("type").asText());
        JsonNode resource = captured.get("resource");
        assertEquals("82e215c4-988a-4f64-8d15-b98b2fc03a4f", resource.get("id").asText());
    }

    /**
     * Test the {@link RestPutDecoderAction#handleRequest(decoder)} method when the decoder has not
     * been updated (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testPutDecoder400() throws IOException {
        // Mock
        RestRequest request = buildRequest(DECODER_PAYLOAD, null);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse expectedResponse =
                new RestResponse("Decoder ID is required.", RestStatus.BAD_REQUEST.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
    }

    /**
     * Test the {@link RestPutDecoderAction#handleRequest(RestRequest)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutDecoder500() throws IOException {
        // Mock
        this.action = new RestPutDecoderAction(null);
        RestRequest request = buildRequest(DECODER_PAYLOAD, "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f");

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

    private Client buildClientForIndex() throws Exception {
        Client client = mock(Client.class, RETURNS_DEEP_STUBS);
        when(client.admin().indices().prepareExists(anyString()).get().isExists()).thenReturn(true);
        @SuppressWarnings("unchecked")
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.get(anyLong(), any())).thenReturn(mock(IndexResponse.class));
        when(client.index(any(IndexRequest.class))).thenReturn(indexFuture);
        return client;
    }

}
