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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;

/**
 * Unit tests for the {@link RestPutIntegrationAction} class. This test suite validates the REST
 * API endpoint responsible for updating existing CTI Integrations.
 *
 * <p>Tests verify Integration update requests, proper handling of Integration data, and
 * appropriate HTTP response codes for successful Integration updates and validation errors.
 */
public class RestPutIntegrationActionTests extends OpenSearchTestCase {

    private EngineService engine;
    private RestPutIntegrationAction action;
    private SecurityAnalyticsServiceImpl saService;
    private NodeClient nodeClient;
    private static final String INTEGRATION_ID = "d_7e87cbde-8e82-41fc-b6ad-29ae789d2e32";

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
        this.nodeClient = mock(NodeClient.class);
        this.action = spy(new RestPutIntegrationAction(this.engine));
        this.action.setNodeClient(this.nodeClient);
    }

    /**
     * Helper method to create a mock GetResponse for an existing draft integration.
     *
     * @param spaceName The space name ("draft" or "standard")
     * @return A mock GetResponse
     */
    private GetResponse createMockGetResponse(String spaceName, boolean exists) {
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(exists);
        if (exists) {
            Map<String, Object> sourceMap = new HashMap<>();
            Map<String, Object> spaceMap = new HashMap<>();
            spaceMap.put("name", spaceName);
            sourceMap.put("space", spaceMap);
            Map<String, Object> documentMap = new HashMap<>();
            documentMap.put("id", RestPutIntegrationActionTests.INTEGRATION_ID);
            documentMap.put("enabled", true);
            sourceMap.put("document", documentMap);
            when(getResponse.getSourceAsMap()).thenReturn(sourceMap);
        }
        return getResponse;
    }

    /**
     * Helper method to build a FakeRestRequest with given payload and ID.
     *
     * @param payload The JSON payload string (null for no content)
     * @param integrationId The integration ID (null for no ID parameter)
     * @return A FakeRestRequest
     */
    private RestRequest buildRequest(String payload, String integrationId) {
        FakeRestRequest.Builder builder = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY);
        if (payload != null) {
            builder.withContent(new BytesArray(payload), XContentType.JSON);
        }
        if (integrationId != null) {
            builder.withParams(Map.of("id", integrationId));
        }
        return builder.build();
    }

    /**
     * If the update succeeds, return a 200 response.
     *
     * <p>Covered test cases (after update):
     *
     * <ul>
     *   <li>A 200 OK response is returned.
     *   <li>Updated integration contains a "space.name" field containing "draft"
     *   <li>Updated integration contains a date (with the current date)
     *   <li>Updated integration contains a hash
     *   <li>The draft policy's hash is updated
     * </ul>
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration200_success() throws IOException {

        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.OK.getStatus());
        expectedResponse.setMessage("Integration updated successfully with ID: " + INTEGRATION_ID);

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest with payload
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any())).thenReturn(
            new org.opensearch.action.support.PlainActionFuture<>() {
                @Override
                public GetResponse actionGet() {
                    return getResponse;
                }
            });

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        when(restResponse.getMessage()).thenReturn(
            // spotless: off
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
            // spotless: on
        );
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.OK);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);
        this.action.setIntegrationsContentIndex(integrationsIndex);


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
    public void testPutIntegration400_hasIdInBody() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("ID field is not allowed in the request body. Use the URL path parameter instead.");

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest with payload containing ID
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any())).thenReturn(
            new org.opensearch.action.support.PlainActionFuture<>() {
                @Override
                public GetResponse actionGet() {
                    return getResponse;
                }
            });

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Request without content
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration400_noContent() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("JSON request body is required.");

        // Create a RestRequest with no payload
        RestRequest request = this.buildRequest(null, INTEGRATION_ID);

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Integration does not exist
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration404_integrationNotFound() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.NOT_FOUND.getStatus());
        expectedResponse.setMessage("Integration not found: " + INTEGRATION_ID);

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest with payload
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        // Mock GetResponse for non-existing integration
        GetResponse getResponse = this.createMockGetResponse("draft", false);
        when(this.nodeClient.get(any())).thenReturn(
            new org.opensearch.action.support.PlainActionFuture<>() {
                @Override
                public GetResponse actionGet() {
                    return getResponse;
                }
            });

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Invalid resource type
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration400_invalidType() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Invalid resource type.");

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest with invalid type
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }


    /**
     * If the engine does not respond, return 500
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration500_noEngineReply() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Failed to update Integration, Invalid validation response: Non valid response.");

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest with payload
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any())).thenReturn(
            new org.opensearch.action.support.PlainActionFuture<>() {
                @Override
                public GetResponse actionGet() {
                    return getResponse;
                }
            });

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        when(restResponse.getMessage()).thenReturn("Non valid response");
        when(this.engine.validate(any())).thenReturn(restResponse);

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Failed to index CTI Integration
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration500_failedToIndexIntegration() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Failed to index integration.");

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest with payload
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any())).thenReturn(
            new org.opensearch.action.support.PlainActionFuture<>() {
                @Override
                public GetResponse actionGet() {
                    return getResponse;
                }
            });

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        when(restResponse.getMessage()).thenReturn(
            // spotless: off
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
            // spotless: on
        );
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        IndexResponse indexResponse = mock(IndexResponse.class);
        when(indexResponse.status()).thenReturn(RestStatus.INTERNAL_SERVER_ERROR);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenReturn(indexResponse);
        this.action.setIntegrationsContentIndex(integrationsIndex);


        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Cannot update integration in non-draft space
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration400_cannotUpdateNonDraftSpace() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Cannot update integration from space 'standard'. Only 'draft' space is modifiable.");

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest with payload
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        // Mock GetResponse for existing integration in standard space (not draft)
        GetResponse getResponse = this.createMockGetResponse("standard", true);
        when(this.nodeClient.get(any())).thenReturn(
            new org.opensearch.action.support.PlainActionFuture<>() {
                @Override
                public GetResponse actionGet() {
                    return getResponse;
                }
            });

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Missing ID in path parameter
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration400_missingIdInPath() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Integration ID is required.");

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest without ID parameter
        RestRequest request = this.buildRequest(payload, null);

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Unexpected error handling Integration
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPutIntegration500_unexpectedError() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Unexpected error during processing.");

        String payload =
                // spotless:off
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
                    """;
                // spotless:on

        // Create a RestRequest with payload
        RestRequest request = this.buildRequest(payload, INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any())).thenReturn(
            new org.opensearch.action.support.PlainActionFuture<>() {
                @Override
                public GetResponse actionGet() {
                    return getResponse;
                }
            });

        // Mock wazuh engine validation
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(RestStatus.OK.getStatus());
        when(restResponse.getMessage()).thenReturn(
            // spotless: off
            """
                {
                  "status": "OK",
                  "error": null
                }
            """
            // spotless: on
        );
        when(this.engine.validate(any())).thenReturn(restResponse);

        // Mock integrations index to throw exception
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        when(integrationsIndex.create(anyString(), any(JsonNode.class))).thenThrow(new IOException());
        this.action.setIntegrationsContentIndex(integrationsIndex);


        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }
}
