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
package com.wazuh.contentmanager.engine.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.rest.model.RestResponse;

/**
 * Unit tests for the {@link EngineSocketClient} class.
 *
 * <p>This test suite validates the Unix socket client functionality including constructor behavior,
 * socket path handling, and error scenarios when the socket doesn't exist.
 *
 * <p>Note: Tests involving actual Unix socket communication require a running Engine service and
 * are better suited for integration tests.
 */
public class EngineSocketClientTests extends OpenSearchTestCase {

    private ObjectMapper objectMapper;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.objectMapper = new ObjectMapper();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /** Test that the default constructor uses the correct default socket path. */
    public void testDefaultConstructorUsesDefaultGetSocketPath() {
        EngineSocketClient client = new EngineSocketClient();

        Assert.assertEquals(
                "/usr/share/wazuh-indexer/engine/sockets/engine-api.sock", client.getSocketPath());
    }

    /** Test that the custom socket path constructor sets the path correctly. */
    public void testCustomGetSocketPathConstructor() {
        String customPath = "/custom/path/socket.sock";
        EngineSocketClient client = new EngineSocketClient(customPath);

        Assert.assertEquals(customPath, client.getSocketPath());
    }

    /** Test that socketPath() accessor returns the correct value. */
    public void testGetSocketPathAccessor() {
        String expectedPath = "/test/socket.sock";
        EngineSocketClient client = new EngineSocketClient(expectedPath);

        Assert.assertEquals(expectedPath, client.getSocketPath());
    }

    /** Test that sendRequest returns 500 status when socket file does not exist. */
    public void testSendRequestReturns500WhenSocketDoesNotExist() {
        EngineSocketClient client = new EngineSocketClient("/non/existent/socket.sock");
        ObjectNode payload = this.objectMapper.createObjectNode();

        RestResponse response = client.sendRequest("/test/endpoint", "POST", payload);

        Assert.assertEquals(500, response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Socket file not found"));
        Assert.assertTrue(response.getMessage().contains("/non/existent/socket.sock"));
    }

    /** Test sendRequest with different non-existent socket paths. */
    public void testSendRequestWithVariousNonExistentPaths() {
        String[] testPaths = {
            "/tmp/nonexistent.sock", "/var/run/missing.sock", "/invalid/path/socket.sock"
        };

        ObjectNode payload = this.objectMapper.createObjectNode();
        payload.put("test", "data");

        for (String path : testPaths) {
            EngineSocketClient client = new EngineSocketClient(path);
            RestResponse response = client.sendRequest("/endpoint", "POST", payload);

            Assert.assertEquals(500, response.getStatus());
            Assert.assertTrue(
                    "Expected error message to contain path: " + path, response.getMessage().contains(path));
        }
    }

    /** Test that socketPath is immutable through the record. */
    public void testGetSocketPathIsImmutable() {
        String originalPath = "/original/path.sock";
        EngineSocketClient client = new EngineSocketClient(originalPath);

        // Verify the path can't be changed (record immutability)
        Assert.assertEquals(originalPath, client.getSocketPath());

        // Create new client with different path
        EngineSocketClient client2 = new EngineSocketClient("/different/path.sock");
        Assert.assertNotEquals(client.getSocketPath(), client2.getSocketPath());
    }

    /** Test sendRequest with empty payload. */
    public void testSendRequestWithEmptyPayload() {
        EngineSocketClient client = new EngineSocketClient("/non/existent/socket.sock");
        ObjectNode emptyPayload = this.objectMapper.createObjectNode();

        RestResponse response = client.sendRequest("/test/endpoint", "POST", emptyPayload);

        // Should fail because socket doesn't exist
        Assert.assertEquals(500, response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Socket file not found"));
    }

    /** Test sendRequest with complex nested JSON payload. */
    public void testSendRequestWithComplexNestedJsonPayload() {
        EngineSocketClient client = new EngineSocketClient("/non/existent/socket.sock");
        ObjectNode payload = this.objectMapper.createObjectNode();
        ObjectNode nested = this.objectMapper.createObjectNode();
        nested.put("key", "value");
        nested.put("number", 42);
        payload.set("nested", nested);
        payload.put("array", this.objectMapper.createArrayNode().add("item1").add("item2"));

        RestResponse response = client.sendRequest("/test/endpoint", "POST", payload);

        // Should fail because socket doesn't exist
        Assert.assertEquals(500, response.getStatus());
    }

    /** Test different HTTP methods with non-existent socket. */
    public void testDifferentHttpMethodsWithNonExistentSocket() {
        String[] methods = {"GET", "POST", "PUT", "DELETE"};
        EngineSocketClient client = new EngineSocketClient("/non/existent/socket.sock");
        ObjectNode payload = this.objectMapper.createObjectNode();

        for (String method : methods) {
            RestResponse response = client.sendRequest("/test/endpoint", method, payload);

            Assert.assertEquals(500, response.getStatus());
            Assert.assertTrue(response.getMessage().contains("Socket file not found"));
        }
    }

    /** Test sendRequest with special characters in payload. */
    public void testSendRequestWithSpecialCharactersInPayload() {
        EngineSocketClient client = new EngineSocketClient("/non/existent/socket.sock");
        ObjectNode payload = this.objectMapper.createObjectNode();
        payload.put("text", "Special: áéíóú ñ €¥£ \n\t\r");
        payload.put("emoji", "🔒🚀");

        RestResponse response = client.sendRequest("/test/endpoint", "POST", payload);

        // Should fail because socket doesn't exist
        Assert.assertEquals(500, response.getStatus());
    }

    /** Test sendRequest with various endpoint paths. */
    public void testSendRequestWithVariousEndpoints() {
        String[] endpoints = {
            "/router/table/get", "/api/v1/logtest", "/validate", "/promote", "/health"
        };
        EngineSocketClient client = new EngineSocketClient("/non/existent/socket.sock");
        ObjectNode payload = this.objectMapper.createObjectNode();

        for (String endpoint : endpoints) {
            RestResponse response = client.sendRequest(endpoint, "POST", payload);

            Assert.assertEquals(500, response.getStatus());
            Assert.assertTrue(response.getMessage().contains("Socket file not found"));
        }
    }
}
