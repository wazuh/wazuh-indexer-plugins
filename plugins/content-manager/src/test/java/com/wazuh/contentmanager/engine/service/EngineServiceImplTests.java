/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.engine.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import com.wazuh.contentmanager.engine.client.EngineSocketClient;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link EngineServiceImpl}.
 *
 * <p>This class contains test cases for the EngineServiceImpl class, covering logtest, validate,
 * promote, and deleteLogtest operations for different response scenarios (200, 201, 204, 400, 500).
 */
public class EngineServiceImplTests extends OpenSearchTestCase {
    private EngineSocketClient socket;
    private EngineServiceImpl engine;
    private final ObjectMapper mapper = new ObjectMapper();

    /** Sets up the test environment before each test method. */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.socket = mock(EngineSocketClient.class);
        this.engine = new EngineServiceImpl(this.socket);
    }

    /** Tests the logtest operation for a successful (200) response. */
    public void testLogtest200() {
        RestResponse expected = new RestResponse("OK", 200);
        when(this.socket.sendRequest(eq(EngineServiceImpl.LOGTEST), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.logtest(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the logtest operation for a bad request (400) response. */
    public void testLogtest400() {
        RestResponse expected = new RestResponse("Bad Request", 400);
        when(this.socket.sendRequest(eq(EngineServiceImpl.LOGTEST), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.logtest(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the logtest operation for an internal server error (500) response. */
    public void testLogtest500() {
        RestResponse expected = new RestResponse("Internal Error", 500);
        when(this.socket.sendRequest(eq(EngineServiceImpl.LOGTEST), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.logtest(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the validate operation for a successful (200) response. */
    public void testValidate200() {
        RestResponse expected = new RestResponse("Valid", 200);
        when(this.socket.sendRequest(eq(EngineServiceImpl.VALIDATE), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.validate(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the validate operation for a bad request (400) response. */
    public void testValidate400() {
        RestResponse expected = new RestResponse("Invalid resource", 400);
        when(this.socket.sendRequest(eq(EngineServiceImpl.VALIDATE), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.validate(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the validate operation for an internal server error (500) response. */
    public void testValidate500() {
        RestResponse expected = new RestResponse("Engine down", 500);
        when(this.socket.sendRequest(eq(EngineServiceImpl.VALIDATE), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.validate(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the promote operation for a successful (200) response. */
    public void testPromote200() {
        RestResponse expected = new RestResponse("Promoted", 200);
        when(this.socket.sendRequest(eq(EngineServiceImpl.PROMOTE), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.promote(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the promote operation for a bad request (400) response. */
    public void testPromote400() {
        RestResponse expected = new RestResponse("Validation failed during promotion", 400);
        when(this.socket.sendRequest(eq(EngineServiceImpl.PROMOTE), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.promote(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the promote operation for an internal server error (500) response. */
    public void testPromote500() {
        RestResponse expected = new RestResponse("Crash", 500);
        when(this.socket.sendRequest(eq(EngineServiceImpl.PROMOTE), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.promote(this.mapper.createObjectNode());
        assertEquals(expected, actual);
    }

    /** Tests the validateResource operation wrapping. */
    public void testValidateResource() {
        RestResponse expected = new RestResponse("Valid Resource Type", 200);
        when(this.socket.sendRequest(eq(EngineServiceImpl.VALIDATE), eq("POST"), any(JsonNode.class)))
                .thenReturn(expected);

        ObjectNode resource = this.mapper.createObjectNode();
        resource.put("title", "Test Rule");

        RestResponse actual = this.engine.validateResource(Constants.KEY_RULE, resource);
        assertEquals(expected, actual);

        // Verify the exact structure wrapped for the socket client
        verify(this.socket)
                .sendRequest(
                        eq(EngineServiceImpl.VALIDATE),
                        eq("POST"),
                        argThat(
                                node ->
                                        node.has(Constants.KEY_TYPE)
                                                && node.get(Constants.KEY_TYPE).asText().equals(Constants.KEY_RULE)
                                                && node.has(Constants.KEY_RESOURCE)
                                                && node.get(Constants.KEY_RESOURCE)
                                                        .get("title")
                                                        .asText()
                                                        .equals("Test Rule")));
    }

    /** Tests the deleteLogtest operation for a successful (200) response. */
    public void testDeleteLogtest200() {
        RestResponse expected = new RestResponse("OK", 200);
        when(this.socket.sendRequest(eq(EngineServiceImpl.LOGTEST), eq("DELETE"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.deleteLogtest();
        assertEquals(expected, actual);
    }

    /** Tests the deleteLogtest operation for an internal server error (500) response. */
    public void testDeleteLogtest500() {
        RestResponse expected = new RestResponse("Engine Socket Error", 500);
        when(this.socket.sendRequest(eq(EngineServiceImpl.LOGTEST), eq("DELETE"), any(JsonNode.class)))
                .thenReturn(expected);

        RestResponse actual = this.engine.deleteLogtest();
        assertEquals(expected, actual);
    }
    public void testPromote500() {}

    /** Tests that loadIocs sends the file path to the correct endpoint. */
    public void testLoadIocsSendsToCorrectEndpoint() {
        String filePath = "/tmp/iocs.ndjson";
        RestResponse expected = new RestResponse("OK", 200);
        when(this.socket.sendRequest(
                        eq(EngineServiceImpl.LOAD_IOCS),
                        eq("POST"),
                        argThat(json -> json.has("path") && json.get("path").asText().equals(filePath))))
                .thenReturn(expected);

        RestResponse result = this.engine.loadIocs(filePath);

        assertEquals(expected, result);
        verify(this.socket)
                .sendRequest(
                        eq(EngineServiceImpl.LOAD_IOCS),
                        eq("POST"),
                        argThat(json -> json.has("path") && json.get("path").asText().equals(filePath)));
    }
}
