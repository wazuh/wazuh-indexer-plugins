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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
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
    private SecurityAnalyticsServiceImpl saService;
    private final ObjectMapper MAPPER = new ObjectMapper();

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
        this.saService = mock(SecurityAnalyticsServiceImpl.class);
        this.action = spy(new RestPostIntegrationAction(this.engine));
    }

    // spotless:off
    /**
     * If the promotion success, return a 200 response.
     *
     * <p>Covered test cases (after promotion):
     *
     * <ul>
     *   <li>A 200 OK response is returned.</li>
     *   <li>Created integration Id is added to the draft policy's "integrations" list</li>
     *   <li>Created integration contains a "modified" field (with the current date)</li>
     *   <li>Created integration contains a "space.name" field containing "draft"</li>
     *   <li>Created integration contains a date (with the current date)</li>
     *   <li>Created integration contains a hash</li>
     *   <li>Created integration has a document Id</li>
     *   <li>Created document Id contains prefix "d_" (for draft)</li>
     *   <li>The draft policy's "space.name" field is updated</li>
     *   <li>The draft policy's hash is updated</li>
     * </ul>
     * </p>
     *
     * @throws IOException if an I/O error occurs during the test
     */
    // spotless:on
    public void testPostIntegration200_success() throws IOException {

        String integrationId = "7e87cbde-8e82-41fc-b6ad-29ae789d2e32";
        when(this.action.generateId()).thenReturn(integrationId);

        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.CREATED.getStatus());
        expectedResponse.setMessage("Integration created successfully with ID: " + integrationId);

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        this.action.setPoliciesContentIndex(policiesIndex);

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        // spotless:off
        when(restResponse.getMessage()).thenReturn(
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
        );
        // spotless:on
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.CREATED);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock draft policy search to return a valid response
        // spotless:off
        String sourceJson =
            """
                {
                  "document": {
                    "author": "Wazuh Inc.",
                    "date": "2025-09-26",
                    "description": "",
                    "documentation": "",
                    "id": "24ef0a2d-5c20-403d-b446-60c6656373a0",
                    "integrations": [
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
                """;
        //spotless:on
        JsonObject hitObject = JsonParser.parseString(sourceJson).getAsJsonObject();
        hitObject.addProperty("id", "24ef0a2d-5c20-403d-b446-60c6656373a0");
        JsonArray hitsArray = new JsonArray();
        hitsArray.add(hitObject);
        JsonObject searchResult = new JsonObject();
        searchResult.add("hits", hitsArray);
        searchResult.addProperty("total", 1);
        when(policiesIndex.searchByQuery(any(QueryBuilder.class))).thenReturn(searchResult);
        IndexResponse indexPolicyResponse = mock(IndexResponse.class);
        when(indexPolicyResponse.status()).thenReturn(RestStatus.OK);
        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexPolicyResponse);

        // spotless:off
        JsonNode mockedPayload =
            FixtureFactory.from(
                """
                    {
                        "type": "integration",
                        "resource":
                        {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                        }
                    }
                    """
            );
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);

        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * If the request payload has an Id, we should return 400
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostIntegration400_hasId() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("ID field is not allowed in the request body.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // spotless:off
        JsonNode mockedPayload =
                FixtureFactory.from(
                """
                    {
                        "type": "integration",
                        "resource":
                        {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate",
                            "id": "9e301671-382"
                        }
                    }
                    """);
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Request without content */
    public void testPostIntegration400_noContent() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("JSON request body is required.");

        // Create a RestRequest with no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(false);

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Draft policy does not exist */
    public void testPostIntegration500_policyDoesNotExist() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Draft policy not found.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        this.action.setPoliciesContentIndex(policiesIndex);
        when(policiesIndex.searchByQuery(any())).thenReturn(null);

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        // spotless:off
        when(restResponse.getMessage()).thenReturn(
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
        );
        // spotless:on
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.CREATED);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // spotless:off
        JsonNode mockedPayload =
                FixtureFactory.from(
                """
                    {
                        "type": "integration",
                        "resource":
                        {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                        }
                    }
                    """);
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Invalid resource type */
    public void testPostIntegration400_invalidType() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Invalid resource type.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // spotless:off
        JsonNode mockedPayload =
            FixtureFactory.from(
                """
                    {
                        "type": "not_integration",
                        "resource":
                        {
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                        }
                    }
                    """

            );
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /** If the engine does not respond, return 500 */
    public void testPostIntegration500_noEngineReply() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage(
                "Failed to create Integration, Invalid validation response: Non valid response.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        this.action.setPoliciesContentIndex(policiesIndex);
        when(policiesIndex.searchByQuery(any())).thenReturn(null);

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        when(restResponse.getMessage()).thenReturn("Non valid response");
        when(this.engine.validate(any())).thenReturn(restResponse);

        // spotless:off
        JsonNode mockedPayload =
                FixtureFactory.from(
                """
                    {
                        "type": "integration",
                        "resource":
                        {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                        }
                    }
                    """);
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Failed to index CTI Integration */
    public void testPostIntegration500_failedToIndexIntegration() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Failed to index integration.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        this.action.setPoliciesContentIndex(policiesIndex);
        when(policiesIndex.searchByQuery(any())).thenReturn(null);

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        // spotless:off
        when(restResponse.getMessage()).thenReturn(
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
        );
        // spotless:on
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.INTERNAL_SERVER_ERROR);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock draft policy search to return a valid response
        // spotless:off
        String sourceJson =
            """
                    {
                        "total": {
                          "value": 0,
                          "relation": "eq"
                        },
                        "max_score": null,
                        "hits": []
                      }
                """;
        //spotless:on
        JsonObject hitObject = JsonParser.parseString(sourceJson).getAsJsonObject();
        hitObject.addProperty("id", "doc-id");
        JsonArray hitsArray = new JsonArray();
        hitsArray.add(hitObject);
        JsonObject searchResult = new JsonObject();
        searchResult.add("hits", hitsArray);
        searchResult.addProperty("total", 1);
        when(policiesIndex.searchByQuery(any(QueryBuilder.class))).thenReturn(searchResult);

        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);

        // spotless:off
        JsonNode mockedPayload =
            FixtureFactory.from(
                """
                    {
                        "type": "integration",
                        "resource":
                        {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                        }
                    }
                    """
            );
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Corrupt draft policy */
    public void testPostIntegration500_corruptDraftPolicy() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage(
                "Failed to retrieve integrations array from draft policy document.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        this.action.setPoliciesContentIndex(policiesIndex);

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        // spotless:off
        when(restResponse.getMessage()).thenReturn(
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
        );
        // spotless:on
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.CREATED);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock draft policy search to return a valid response
        // spotless:off
        String sourceJson =
            """
            {
                "document": "corrupt_data"
            }
            """;
        //spotless:on
        JsonObject hitObject = JsonParser.parseString(sourceJson).getAsJsonObject();
        hitObject.addProperty("id", "24ef0a2d-5c20-403d-b446-60c6656373a0");
        JsonArray hitsArray = new JsonArray();
        hitsArray.add(hitObject);
        JsonObject searchResult = new JsonObject();
        searchResult.add("hits", hitsArray);
        searchResult.addProperty("total", 1);
        when(policiesIndex.searchByQuery(any(QueryBuilder.class))).thenReturn(searchResult);
        IndexResponse indexPolicyResponse = mock(IndexResponse.class);
        when(indexPolicyResponse.status()).thenReturn(RestStatus.OK);
        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexPolicyResponse);

        // spotless:off
        JsonNode mockedPayload =
            FixtureFactory.from(
                """
                    {
                        "type": "integration",
                        "resource":
                        {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                        }
                    }
                    """
            );
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Failed to update draft policy */
    public void testPostIntegration500_draftPolicyFailedUpdate() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Failed to update draft policy.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        this.action.setPoliciesContentIndex(policiesIndex);

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        // spotless:off
        when(restResponse.getMessage()).thenReturn(
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
        );
        // spotless:on
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.CREATED);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock draft policy search to return a valid response
        // spotless:off
        String sourceJson =
            """
            {
              "document": {
                "author": "Wazuh Inc.",
                "date": "2025-09-26",
                "description": "",
                "documentation": "",
                "id": "24ef0a2d-5c20-403d-b446-60c6656373a0",
                "integrations": [
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
                "name": "standard",
                "hash": {
                  "sha256": "97946e6bdbe0a846b853d187e67a5d5403b32c7d13a04d25c076280e75234c9d"
                }
              }
            }
           """;
        //spotless:on
        JsonObject hitObject = JsonParser.parseString(sourceJson).getAsJsonObject();
        hitObject.addProperty("id", "24ef0a2d-5c20-403d-b446-60c6656373a0");
        JsonArray hitsArray = new JsonArray();
        hitsArray.add(hitObject);
        JsonObject searchResult = new JsonObject();
        searchResult.add("hits", hitsArray);
        searchResult.addProperty("total", 1);
        when(policiesIndex.searchByQuery(any(QueryBuilder.class))).thenReturn(searchResult);
        IndexResponse indexPolicyResponse = mock(IndexResponse.class);
        when(indexPolicyResponse.status()).thenReturn(RestStatus.INTERNAL_SERVER_ERROR);
        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexPolicyResponse);

        // spotless:off
        JsonNode mockedPayload =
            FixtureFactory.from(
                """
                    {
                        "type": "integration",
                        "resource":
                        {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                        }
                    }
                    """
            );
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);
        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /** Unexpected error handling Integration */
    public void testPostIntegration500_unexpectedError() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Unexpected error during processing.");

        // Create a RestRequest with the no payload
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        this.action.setPoliciesContentIndex(policiesIndex);

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        // spotless:off
        when(restResponse.getMessage()).thenReturn(
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
        );
        // spotless:on
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.OK);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenThrow(new IOException());
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock draft policy search to return a valid response
        // spotless:off
        String sourceJson =
            """
                     {
                       "total": {
                         "value": 1,
                         "relation": "eq"
                       },
                       "max_score": 1,
                       "hits": [
                         {
                           "_index": ".decoders_development_0.0.2-decoders_development_0.0.2_test-policy",
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
                               "name": "standard",
                               "hash": {
                                 "sha256": "97946e6bdbe0a846b853d187e67a5d5403b32c7d13a04d25c076280e75234c9d"
                               }
                             }
                           }
                         }
                       ]
                     }
               """;
        // spotless:on
        JsonObject hitObject = JsonParser.parseString(sourceJson).getAsJsonObject();
        hitObject.addProperty("id", "doc-id");
        JsonArray hitsArray = new JsonArray();
        hitsArray.add(hitObject);
        JsonObject searchResult = new JsonObject();
        searchResult.add("hits", hitsArray);
        searchResult.addProperty("total", 1);
        when(policiesIndex.searchByQuery(any(QueryBuilder.class))).thenReturn(searchResult);

        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);

        // spotless:off
        JsonNode mockedPayload =
            FixtureFactory.from(
                """
                    {
                        "type": "integration",
                        "resource":
                        {
                            "author": "Wazuh Inc.",
                            "category": "cloud-services",
                            "decoders": [
                              "1cb80fdb-7209-4b96-8bd1-ec15864d0f35"
                            ],
                            "description": "This integration supports AWS Fargate logs.",
                            "documentation": "",
                            "kvdbs": [],
                            "references": [
                              "https://wazuh.com"
                            ],
                            "rules": [],
                            "title": "aws-fargate"
                        }
                    }
                    """
            );
        // spotless:on
        when(request.content())
                .thenReturn(new BytesArray(this.MAPPER.writeValueAsBytes(mockedPayload)));

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }
}
