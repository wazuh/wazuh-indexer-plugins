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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.io.IOException;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
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
    private SecurityAnalyticsServiceImpl saService;

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
        this.saService = mock(SecurityAnalyticsServiceImpl.class);
        this.action = spy(new RestPostIntegrationAction(this.engine, this.saService));
    }

    /**
     * Test the {@link RestPostIntegrationAction#handleRequest(RestRequest)} method when the
     * request is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration200() throws IOException {

        // Integration JSON document to be created

        JsonNode integrationJson =
                new ObjectMapper()
                        .readTree(
                                // spotless:off
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
            }"""
            // spotless:on
                                );

        // Set the expected payload as sent to the Wazuh Engine for validation
        ObjectNode expectedPayload =
                (ObjectNode)
                        new ObjectMapper()
                                .readTree(
                                        // spotless:off
            """
            {
              "type": "integration",
              "resource": {}
            }"""
            // spotless:on
                                        );

        expectedPayload.set("resource", integrationJson);

        String integrationId = "d_9e301671-382d-4c1a-9abf-3d9d9544789c";
        when(this.action.generateId()).thenReturn(integrationId);

        // Prepare the request
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(expectedPayload.toString().getBytes()));

        WIndexIntegrationResponse mockWindexResponse = mock(WIndexIntegrationResponse.class);
        when(this.saService.upsertIntegration(any(JsonNode.class))).thenReturn(mockWindexResponse);
        when(mockWindexResponse.getStatus()).thenReturn(RestStatus.OK);

        ContentIndex integrationsIndex = mock(ContentIndex.class);
        ContentIndex policiesIndex = mock(ContentIndex.class);
        this.action.setIntegrationsContentIndex(integrationsIndex);
        this.action.setPoliciesContentIndex(policiesIndex);
        IndexResponse integrationsIndexResponse = mock(IndexResponse.class);
        when(integrationsIndexResponse.status()).thenReturn(RestStatus.OK);

        when(integrationsIndex.create(anyString(), any(JsonNode.class)))
                .thenReturn(integrationsIndexResponse);

        JsonObject searchResult =
                JsonParser.parseString(
                                // spotless:off
            """
                {
                    "total": {
                      "value": 1,
                      "relation": "eq"
                    },
                    "max_score": 1,
                    "hits": [
                      {
                        "_index": ".cti-policies",
                        "_id": "24ef0a2d-5c20-403d-b446-60c6656373a0",
                        "_score": 1,
                        "_source": {
                          "document": {
                            "author": "Wazuh Inc.",
                            "date": "2025-09-26",
                            "description": "",
                            "documentation": "",
                            "id": "24ef0a2d-5c20-403d-b446-60c6656373a0",
                            "integrations": [
                              "1cc276a0-7670-4957-b814-20ba14df0a6d",
                              "91dd2edc-9658-49f1-b790-c4c76a5c1bb2",
                              "21a3c2cc-901d-4e5f-9543-7f0f921747d2",
                              "7e87cbde-8e82-41fc-b6ad-29ae789d2e32"
                            ],
                            "modified": "2026-01-15",
                            "references": [
                              "https://wazuh.com"
                            ],
                            "root_decoder": "a1f330f4-8012-48ab-9949-c5d76edaf9b1",
                            "title": "Development 0.0.1"
                          },
                          "hash": {
                            "sha256": "50730c07b86446e82b51fabcec21e279451431d6ce40ee87ef2d28055435b301"
                          },
                          "space": {
                            "name": "draft",
                            "hash": {
                              "sha256": "97946e6bdbe0a846b853d187e67a5d5403b32c7d13a04d25c076280e75234c9d"
                            }
                          }
                        }
                      }
                    ]
                  }
            """
            //spotless:on
                                )
                        .getAsJsonObject();
        when(policiesIndex.searchByQuery(any())).thenReturn(searchResult);

        // Make the engine return a successful response for the validation
        when(this.engine.validate(any(JsonNode.class)))
                .thenReturn(
                        new RestResponse(
                                // spotless:off
            """
            {
              "status": "OK",
              "error": null
            }"""
            // spotless:on
                                ,
                                200));

        IndexResponse indexPolicyResponse = mock(IndexResponse.class);
        when(indexPolicyResponse.status()).thenReturn(RestStatus.OK);
        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexPolicyResponse);

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        doNothing()
                .when(policyHashService)
                .calculateAndUpdate(any(), any(), any(), any(), any(), any());
        this.action.setPolicyHashService(policyHashService);

        // Execute the tested method
        RestResponse response = this.action.handleRequest(request);

        assertEquals(200, response.getStatus());
        assertEquals(
                "Integration created successfully with ID: " + integrationId + ".", response.getMessage());

        // Verify that the engine service validated the expected payload
        verify(this.engine, times(1)).validate(any());

        // Verify that the client executed the expected action
        verify(this.saService, times(1)).upsertIntegration(any(JsonNode.class));
        verify(this.saService, never()).deleteIntegration(anyString());
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
                                // spotless:off
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
            }"""
            // spotless:on
                                );

        // Set the expected payload as sent to the Wazuh Engine for validation
        ObjectNode expectedPayload =
                (ObjectNode)
                        new ObjectMapper()
                                .readTree(
                                        // spotless:off
            """
            {
              "type": "integration",
              "resource": {}
            }"""
            // spotless:on
                                        );
        expectedPayload.set("resource", integrationJson.get("document"));

        // Prepare the request
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(expectedPayload.toString().getBytes()));

        // Make the engine return a validation error
        when(this.engine.validate(any(JsonNode.class)))
                .thenReturn(
                        new RestResponse(
                                // spotless:off
            """
            {
              "status": "ERROR",
              "error": {
                "message": "Validation failed"
              }
            }"""
            // spotless:on
                                ,
                                400));

        // Execute the tested method
        RestResponse response = this.action.handleRequest(request);

        assertEquals(400, response.getStatus());
        assertEquals(
                // spotless:off
            """
            {
              "status": "ERROR",
              "error": {
                "message": "Validation failed"
              }
            }"""
            // spotless:on
                ,
                response.getMessage());

        // Verify that the engine service validated the expected payload
        verify(this.engine, times(1)).validate(expectedPayload);

        // Ensure we don't attempt to index the integration when validation fails
        verify(this.client, times(0)).execute(any(WIndexIntegrationAction.class), any());
    }

    /**
     * Test the {@link RestPostIntegrationAction#handleRequest(RestRequest)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration500() throws IOException {

        // Integration JSON document to be created
        JsonNode integrationJson =
                new ObjectMapper()
                        .readTree(
                                // spotless:off
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
            }"""
            // spotless:on
                                );

        // Set the expected payload as sent to the Wazuh Engine for validation
        ObjectNode expectedPayload =
                (ObjectNode)
                        new ObjectMapper()
                                .readTree(
                                        // spotless:off
            """
                    {
                      "type": "integration",
                      "resource": {}
                    }
                """
            // spotless:on
                                        );
        expectedPayload.set("resource", integrationJson.get("document"));

        // Prepare the request
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray("Internal Server Error".getBytes()));

        // Make the engine return a validation error
        when(this.engine.validate(any(JsonNode.class)))
                .thenReturn(new RestResponse("Internal Server Error", 500));

        // Execute the tested method
        RestResponse response = this.action.handleRequest(request);

        assertEquals(500, response.getStatus());
        assertEquals("Internal Server Error", response.getMessage());

        // Verify that the engine service validated the expected payload
        verify(this.engine, times(1)).validate(expectedPayload);

        // Ensure we don't attempt to index the integration when validation fails
        verify(this.client, times(0)).execute(any(WIndexIntegrationAction.class), any());
    }
}
