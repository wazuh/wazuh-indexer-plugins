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
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;

import com.wazuh.contentmanager.engine.services.EngineService;
import org.opensearch.transport.client.Client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestPostIntegrationAction} class. This test suite validates the REST
 * API endpoint responsible for creating new CTI Integrations.
 *
 * <p>Tests verify Integration creation requests, proper handling of Integration data, and
 * appropriate HTTP response codes for successful Integration creation and validation errors.
 */
public class RestPostIntegrationActionTests extends OpenSearchTestCase {

    private EngineService engine;
    private RestPostIntegrationAction action;
    private Client client;

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
        this.client = mock(Client.class);
        SecurityAnalyticsServiceImpl saService = new SecurityAnalyticsServiceImpl(this.client);
        this.action = new RestPostIntegrationAction(this.engine, saService);
    }

    /**
     * Test the {@link RestPostIntegrationAction#handleRequest(RestRequest)} method when the request
     * is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration200() throws IOException {

        // Integration JSON document to be created

        JsonNode integrationJson =
            new ObjectMapper()
                .readTree(
                    """
                        {
                          "document": {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "date": "2025-10-08",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "enabled": true,
                            "id": "9e301671-382d-4c1a-9abf-3d9d9544789c",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                          },
                          "hash": {
                            "sha256": "3b2fc76ba88ddbf67a3807c53d0f563467a4d5b996b62e68e8ebc322ada846f5"
                          },
                          "space": {
                            "name": "standard"
                          }
                        }""");

        // Set the expected payload as sent to the Wazuh Engine for validation
        ObjectNode expectedPayload = (ObjectNode) new ObjectMapper().readTree("""
            {
              "type": "integration",
              "resource": {}
            }""");

        expectedPayload.set("resource", integrationJson.get("document"));

        // Prepare the request
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(expectedPayload.toString().getBytes()));

        // Make the engine return a successful response for the validation
        when(this.engine.validate(any(JsonNode.class)))
            .thenReturn(new RestResponse("""
                {
                  "status": "OK",
                  "error": null
                }""", 200));

        // Execute the tested method
        RestResponse response = this.action.handleRequest(request);

        assertEquals(200, response.getStatus());
        assertEquals("""
            {
              "status": "OK",
              "error": null
            }""", response.getMessage());

        // Verify that the engine service validated the expected payload
        verify(this.engine, times(1)).validate(expectedPayload);

        // Verify that the client executed the expected action
        verify(this.client, times(1)).execute(any(WIndexIntegrationAction.class), any());


    }

    /**
     * Test the {@link RestPostIntegrationAction#handleRequest(RestRequest)} method when the
     * integration has not been created (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration400() throws IOException {

        // Integration JSON document to be created
        JsonNode integrationJson =
            new ObjectMapper()
                .readTree(
                    """
                        {
                          "document": {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "date": "2025-10-08",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "enabled": true,
                            "id": "9e301671-382d-4c1a-9abf-3d9d9544789c",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                          },
                          "hash": {
                            "sha256": "3b2fc76ba88ddbf67a3807c53d0f563467a4d5b996b62e68e8ebc322ada846f5"
                          },
                          "space": {
                            "name": "standard"
                          }
                        }""");

        // Set the expected payload as sent to the Wazuh Engine for validation
        ObjectNode expectedPayload = (ObjectNode) new ObjectMapper().readTree(
            """
                {
                  "type": "integration",
                  "resource": {}
                }""");
        expectedPayload.set("resource", integrationJson.get("document"));

        // Prepare the request
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(expectedPayload.toString().getBytes()));

        // Make the engine return a validation error
        when(this.engine.validate(any(JsonNode.class)))
            .thenReturn(
                new RestResponse(
                    """
                        {
                          "status": "ERROR",
                          "error": {
                            "message": "Validation failed"
                          }
                        }""",
                    400));

        // Execute the tested method
        RestResponse response = this.action.handleRequest(request);

        assertEquals(400, response.getStatus());
        assertEquals(
            """
                {
                  "status": "ERROR",
                  "error": {
                    "message": "Validation failed"
                  }
                }""",
            response.getMessage());

        // Verify that the engine service validated the expected payload
        verify(this.engine, times(1)).validate(expectedPayload);

        // Ensure we don't attempt to index the integration when validation fails
        verify(this.client, times(0)).execute(any(WIndexIntegrationAction.class), any());
    }

    /**
     * Test the {@link RestPostIntegrationAction#handleRequest(RestRequest)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     */
    public void testPostIntegration500() throws IOException {

        // Integration JSON document to be created
        JsonNode integrationJson =
            new ObjectMapper()
                .readTree(
                    """
                        {
                          "document": {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "date": "2025-10-08",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "enabled": true,
                            "id": "9e301671-382d-4c1a-9abf-3d9d9544789c",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                          },
                          "hash": {
                            "sha256": "3b2fc76ba88ddbf67a3807c53d0f563467a4d5b996b62e68e8ebc322ada846f5"
                          },
                          "space": {
                            "name": "standard"
                          }
                        }""");

        // Set the expected payload as sent to the Wazuh Engine for validation
        ObjectNode expectedPayload = (ObjectNode) new ObjectMapper().readTree(
            """
                {
                  "type": "integration",
                  "resource": {}
                }""");
        expectedPayload.set("resource", integrationJson.get("document"));

        // Prepare the request
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray("Internal Server Error".getBytes()));

        // Make the engine return a validation error
        when(this.engine.validate(any(JsonNode.class)))
            .thenReturn(
                new RestResponse(
                    "Internal Server Error",
                    500));

        // Execute the tested method
        RestResponse response = this.action.handleRequest(request);

        assertEquals(500, response.getStatus());
        assertEquals("Internal Server Error",
            response.getMessage());

        // Verify that the engine service validated the expected payload
        verify(this.engine, times(1)).validate(expectedPayload);

        // Ensure we don't attempt to index the integration when validation fails
        verify(this.client, times(0)).execute(any(WIndexIntegrationAction.class), any());
    }
}
