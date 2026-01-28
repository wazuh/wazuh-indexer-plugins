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

import static org.mockito.Mockito.mock;

/**
 * Unit tests for the {@link RestDeleteDecoderAction} class. This test suite validates the REST API
 * endpoint responsible for deleting new CTI Decoders.
 *
 * <p>Tests verify Decoder delete requests, proper handling of Decoder data, and appropriate HTTP
 * response codes for successful Decoder delete errors.
 */
public class RestDeleteDecoderActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestDeleteDecoderAction action;

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
        this.action = new RestDeleteDecoderAction(this.service);
    }

    /**
     * Test the {@link RestDeleteDecoderAction#handleRequest(RestRequest)} method when the request is
     * complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteDecoder200() throws IOException {
        // Mock
        RestRequest request = buildRequest(null, "82e215c4-988a-4f64-8d15-b98b2fc03a4f");

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(request, null);

        // Assert
        RestResponse expectedResponse =
                new RestResponse("Decoder deleted successfully.", RestStatus.OK.getStatus());
        RestResponse actualResponse = parseResponse(bytesRestResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(RestStatus.OK, bytesRestResponse.status());
    }

    /**
     * Test the {@link RestDeleteDecoderAction#handleRequest(RestRequest)} method when the decoder has
     * not been deleted (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteDecoder400() throws IOException {
        // Mock
        RestRequest request = buildRequest(null, null);

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
     * Test the {@link RestDeleteDecoderAction#handleRequest(RestRequest)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteDecoder500() throws IOException {
        // Mock
        this.action = new RestDeleteDecoderAction(null);
        RestRequest request = buildRequest(null, "82e215c4-988a-4f64-8d15-b98b2fc03a4f");

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
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY);
        if (payload != null) {
            builder.withContent(new BytesArray(payload), XContentType.JSON);
        }
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
