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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;
import org.junit.Before;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestDeleteIntegrationAction} class. This test suite validates the REST
 * API endpoint responsible for deleting CTI Integrations from the draft space.
 *
 * <p>Tests verify Integration delete requests, proper handling of space validation, and appropriate
 * HTTP response codes for successful deletions and validation errors.
 */
public class RestDeleteIntegrationActionTests extends OpenSearchTestCase {

    private EngineService engine;
    private RestDeleteIntegrationAction action;
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
        this.action = spy(new RestDeleteIntegrationAction(this.engine));
        this.action.setNodeClient(this.nodeClient);
    }

    /**
     * Helper method to create a mock GetResponse for an existing draft integration.
     *
     * @param spaceName The space name ("draft" or "standard")
     * @param exists Whether the integration exists
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
            documentMap.put("id", RestDeleteIntegrationActionTests.INTEGRATION_ID);
            documentMap.put("enabled", true);
            sourceMap.put("document", documentMap);
            when(getResponse.getSourceAsMap()).thenReturn(sourceMap);
        }
        return getResponse;
    }

    /**
     * Helper method to create a mock draft policy search result.
     *
     * @param integrationId The integration ID to include in the integrations array
     * @return A mock JsonObject representing the search result
     */
    private JsonObject createMockDraftPolicySearchResult(String integrationId) {
        JsonObject searchResult = new JsonObject();
        JsonArray hitsArray = new JsonArray();

        JsonObject policyHit = new JsonObject();
        policyHit.addProperty("id", "draft-policy-id");

        JsonObject document = new JsonObject();
        JsonArray integrations = new JsonArray();
        integrations.add(integrationId);
        integrations.add("other-integration-id");
        document.add("integrations", integrations);

        JsonObject hash = new JsonObject();
        hash.addProperty("sha256", "abc123def456");

        policyHit.add("document", document);
        policyHit.add("hash", hash);

        hitsArray.add(policyHit);
        searchResult.add("hits", hitsArray);

        return searchResult;
    }

    /**
     * Helper method to build a FakeRestRequest with given ID parameter.
     *
     * @param integrationId The integration ID (null for no ID parameter)
     * @return A FakeRestRequest
     */
    private RestRequest buildRequest(String integrationId) {
        FakeRestRequest.Builder builder = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY);
        if (integrationId != null) {
            builder.withParams(Map.of("id", integrationId));
        }
        return builder.build();
    }

    /**
     * If the delete succeeds, return a 200 response.
     *
     * <p>Covered test cases:
     *
     * <ul>
     *   <li>A 200 OK response is returned.
     *   <li>Integration exists in draft space
     *   <li>Integration is deleted from Security Analytics Plugin
     *   <li>Integration is deleted from CTI integrations index
     *   <li>Integration ID is removed from draft policy's integrations array
     *   <li>The draft policy's hash is updated
     * </ul>
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration200_success() throws IOException {

        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.OK.getStatus());
        expectedResponse.setMessage("Integration deleted successfully with ID: " + INTEGRATION_ID);

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any()))
                .thenReturn(
                        new org.opensearch.action.support.PlainActionFuture<>() {
                            @Override
                            public GetResponse actionGet() {
                                return getResponse;
                            }
                        });

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        doNothing().when(integrationsIndex).delete(any());
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        String integrationIdWithoutPrefix = INTEGRATION_ID.substring(2);
        JsonObject draftPolicySearchResult =
                this.createMockDraftPolicySearchResult(integrationIdWithoutPrefix);
        when(policiesIndex.searchByQuery(any(TermQueryBuilder.class)))
                .thenReturn(draftPolicySearchResult);

        // Mock policy index response
        IndexResponse policyIndexResponse = mock(IndexResponse.class);
        when(policyIndexResponse.status()).thenReturn(RestStatus.OK);
        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(policyIndexResponse);
        this.action.setPoliciesContentIndex(policiesIndex);

        // Mock Security Analytics service
        doNothing().when(this.saService).deleteIntegration(any());
        this.action.setSecurityAnalyticsService(this.saService);

        // Mock policy hash service
        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);

        // Verify delete was called
        verify(integrationsIndex).delete(INTEGRATION_ID);
        verify(this.saService).deleteIntegration(INTEGRATION_ID);
        // Verify policy was updated
        verify(policiesIndex).create(anyString(), any(JsonNode.class));
    }

    /**
     * Integration does not exist
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration404_integrationNotFound() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.NOT_FOUND.getStatus());
        expectedResponse.setMessage("Integration not found: " + INTEGRATION_ID);

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for non-existing integration
        GetResponse getResponse = this.createMockGetResponse("draft", false);
        when(this.nodeClient.get(any()))
                .thenReturn(
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
     * Cannot delete integration in non-draft space
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration400_cannotDeleteNonDraftSpace() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage(
                "Cannot delete integration from space 'standard'. Only 'draft' space is modifiable.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration in standard space (not draft)
        GetResponse getResponse = this.createMockGetResponse("standard", true);
        when(this.nodeClient.get(any()))
                .thenReturn(
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
    public void testDeleteIntegration400_missingIdInPath() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Integration ID is required.");

        // Create a RestRequest without ID parameter
        RestRequest request = this.buildRequest(null);

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Security Analytics service is null
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration500_securityAnalyticsServiceNull() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Security Analytics service instance is null.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Don't set Security Analytics service (leave it null)

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Failed to retrieve integration from index
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration500_failedToRetrieveIntegration() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Failed to retrieve existing integration.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse to throw exception
        when(this.nodeClient.get(any()))
                .thenReturn(
                        new org.opensearch.action.support.PlainActionFuture<>() {
                            @Override
                            public GetResponse actionGet() {
                                throw new RuntimeException("Index not found");
                            }
                        });

        this.action.setSecurityAnalyticsService(this.saService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Unexpected error during delete operation
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration500_unexpectedError() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Unexpected error during processing.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any()))
                .thenReturn(
                        new org.opensearch.action.support.PlainActionFuture<>() {
                            @Override
                            public GetResponse actionGet() {
                                return getResponse;
                            }
                        });

        // Mock Security Analytics service
        doNothing().when(this.saService).deleteIntegration(any());
        this.action.setSecurityAnalyticsService(this.saService);

        // Mock integrations index to throw exception
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        doThrow(new RuntimeException("Unexpected error")).when(integrationsIndex).delete(any());
        this.action.setIntegrationsContentIndex(integrationsIndex);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Integration has undefined space
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration400_undefinedSpace() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Cannot delete integration with undefined space.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration without space field
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> sourceMap = new HashMap<>();
        // No space field added
        Map<String, Object> documentMap = new HashMap<>();
        documentMap.put("id", INTEGRATION_ID);
        sourceMap.put("document", documentMap);
        when(getResponse.getSourceAsMap()).thenReturn(sourceMap);

        when(this.nodeClient.get(any()))
                .thenReturn(
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
     * Verify that Security Analytics deletion failure doesn't stop the overall deletion process
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration200_securityAnalyticsFailureDoesNotBlock() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.OK.getStatus());
        expectedResponse.setMessage("Integration deleted successfully with ID: " + INTEGRATION_ID);

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any()))
                .thenReturn(
                        new org.opensearch.action.support.PlainActionFuture<>() {
                            @Override
                            public GetResponse actionGet() {
                                return getResponse;
                            }
                        });

        // Mock Security Analytics service to throw exception (but should not block deletion)
        doThrow(new RuntimeException("SAP error")).when(this.saService).deleteIntegration(any());
        this.action.setSecurityAnalyticsService(this.saService);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        doNothing().when(integrationsIndex).delete(any());
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        String integrationIdWithoutPrefix = INTEGRATION_ID.substring(2);
        JsonObject draftPolicySearchResult =
                this.createMockDraftPolicySearchResult(integrationIdWithoutPrefix);
        when(policiesIndex.searchByQuery(any(TermQueryBuilder.class)))
                .thenReturn(draftPolicySearchResult);

        // Mock policy index response
        IndexResponse policyIndexResponse = mock(IndexResponse.class);
        when(policyIndexResponse.status()).thenReturn(RestStatus.OK);
        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(policyIndexResponse);
        this.action.setPoliciesContentIndex(policiesIndex);

        // Mock policy hash service
        PolicyHashService policyHashService = mock(PolicyHashService.class);
        this.action.setPolicyHashService(policyHashService);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);

        // Verify delete was still called on integrations index despite SAP failure
        verify(integrationsIndex).delete(INTEGRATION_ID);
    }

    /**
     * Draft policy not found during delete operation
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration500_draftPolicyNotFound() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Draft policy not found.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any()))
                .thenReturn(
                        new org.opensearch.action.support.PlainActionFuture<>() {
                            @Override
                            public GetResponse actionGet() {
                                return getResponse;
                            }
                        });

        // Mock Security Analytics service
        doNothing().when(this.saService).deleteIntegration(any());
        this.action.setSecurityAnalyticsService(this.saService);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        doNothing().when(integrationsIndex).delete(any());
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock policies index to return empty result
        ContentIndex policiesIndex = mock(ContentIndex.class);
        JsonObject emptySearchResult = new JsonObject();
        emptySearchResult.add("hits", new JsonArray());
        when(policiesIndex.searchByQuery(any(TermQueryBuilder.class))).thenReturn(emptySearchResult);
        this.action.setPoliciesContentIndex(policiesIndex);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Draft policy document is missing
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration500_draftPolicyDocumentMissing() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Failed to retrieve draft policy document.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any()))
                .thenReturn(
                        new org.opensearch.action.support.PlainActionFuture<>() {
                            @Override
                            public GetResponse actionGet() {
                                return getResponse;
                            }
                        });

        // Mock Security Analytics service
        doNothing().when(this.saService).deleteIntegration(any());
        this.action.setSecurityAnalyticsService(this.saService);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        doNothing().when(integrationsIndex).delete(any());
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock policies index to return policy without document field
        ContentIndex policiesIndex = mock(ContentIndex.class);
        JsonObject searchResult = new JsonObject();
        JsonArray hitsArray = new JsonArray();
        JsonObject policyHit = new JsonObject();
        policyHit.addProperty("id", "draft-policy-id");
        // No document field
        hitsArray.add(policyHit);
        searchResult.add("hits", hitsArray);
        when(policiesIndex.searchByQuery(any(TermQueryBuilder.class))).thenReturn(searchResult);
        this.action.setPoliciesContentIndex(policiesIndex);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Draft policy integrations array is missing
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration500_draftPolicyIntegrationsArrayMissing() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage(
                "Failed to retrieve integrations array from draft policy document.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any()))
                .thenReturn(
                        new org.opensearch.action.support.PlainActionFuture<>() {
                            @Override
                            public GetResponse actionGet() {
                                return getResponse;
                            }
                        });

        // Mock Security Analytics service
        doNothing().when(this.saService).deleteIntegration(any());
        this.action.setSecurityAnalyticsService(this.saService);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        doNothing().when(integrationsIndex).delete(any());
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock policies index to return policy without integrations array
        ContentIndex policiesIndex = mock(ContentIndex.class);
        JsonObject searchResult = new JsonObject();
        JsonArray hitsArray = new JsonArray();
        JsonObject policyHit = new JsonObject();
        policyHit.addProperty("id", "draft-policy-id");
        JsonObject document = new JsonObject();
        // No integrations array
        JsonObject hash = new JsonObject();
        hash.addProperty("sha256", "abc123");
        policyHit.add("document", document);
        policyHit.add("hash", hash);
        hitsArray.add(policyHit);
        searchResult.add("hits", hitsArray);
        when(policiesIndex.searchByQuery(any(TermQueryBuilder.class))).thenReturn(searchResult);
        this.action.setPoliciesContentIndex(policiesIndex);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Failed to update draft policy
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteIntegration500_failedToUpdateDraftPolicy() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        expectedResponse.setMessage("Failed to update draft policy.");

        // Create a RestRequest with ID parameter
        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse for existing integration in draft space
        GetResponse getResponse = this.createMockGetResponse("draft", true);
        when(this.nodeClient.get(any()))
                .thenReturn(
                        new org.opensearch.action.support.PlainActionFuture<>() {
                            @Override
                            public GetResponse actionGet() {
                                return getResponse;
                            }
                        });

        // Mock Security Analytics service
        doNothing().when(this.saService).deleteIntegration(any());
        this.action.setSecurityAnalyticsService(this.saService);

        // Mock integrations index
        ContentIndex integrationsIndex = mock(ContentIndex.class);
        doNothing().when(integrationsIndex).delete(any());
        this.action.setIntegrationsContentIndex(integrationsIndex);

        // Mock policies index
        ContentIndex policiesIndex = mock(ContentIndex.class);
        String integrationIdWithoutPrefix = INTEGRATION_ID.substring(2);
        JsonObject draftPolicySearchResult =
                this.createMockDraftPolicySearchResult(integrationIdWithoutPrefix);
        when(policiesIndex.searchByQuery(any(TermQueryBuilder.class)))
                .thenReturn(draftPolicySearchResult);

        // Mock policy index response to fail
        IndexResponse policyIndexResponse = mock(IndexResponse.class);
        when(policyIndexResponse.status()).thenReturn(RestStatus.INTERNAL_SERVER_ERROR);
        when(policiesIndex.create(anyString(), any(JsonNode.class))).thenReturn(policyIndexResponse);
        this.action.setPoliciesContentIndex(policiesIndex);

        RestResponse actualResponse = this.action.handleRequest(request);
        assertEquals(expectedResponse, actualResponse);
    }

    public void testDeleteIntegration400_hasDecoders() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Cannot delete integration because it has decoders attached.");

        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse with decoders
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> sourceMap = new HashMap<>();
        Map<String, Object> spaceMap = new HashMap<>();
        spaceMap.put("name", "draft");
        sourceMap.put("space", spaceMap);
        Map<String, Object> documentMap = new HashMap<>();
        documentMap.put("id", INTEGRATION_ID);
        documentMap.put("decoders", java.util.List.of("decoder_1"));
        sourceMap.put("document", documentMap);
        when(getResponse.getSourceAsMap()).thenReturn(sourceMap);

        when(this.nodeClient.get(any()))
                .thenReturn(
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

    public void testDeleteIntegration400_hasRules() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Cannot delete integration because it has rules attached.");

        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse with rules
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> sourceMap = new HashMap<>();
        Map<String, Object> spaceMap = new HashMap<>();
        spaceMap.put("name", "draft");
        sourceMap.put("space", spaceMap);
        Map<String, Object> documentMap = new HashMap<>();
        documentMap.put("id", INTEGRATION_ID);
        documentMap.put("rules", java.util.List.of("rule_1"));
        sourceMap.put("document", documentMap);
        when(getResponse.getSourceAsMap()).thenReturn(sourceMap);

        when(this.nodeClient.get(any()))
                .thenReturn(
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

    public void testDeleteIntegration400_hasKvdbs() throws IOException {
        RestResponse expectedResponse = new RestResponse();
        expectedResponse.setStatus(RestStatus.BAD_REQUEST.getStatus());
        expectedResponse.setMessage("Cannot delete integration because it has kvdbs attached.");

        RestRequest request = this.buildRequest(INTEGRATION_ID);

        // Mock GetResponse with kvdbs
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        Map<String, Object> sourceMap = new HashMap<>();
        Map<String, Object> spaceMap = new HashMap<>();
        spaceMap.put("name", "draft");
        sourceMap.put("space", spaceMap);
        Map<String, Object> documentMap = new HashMap<>();
        documentMap.put("id", INTEGRATION_ID);
        documentMap.put("kvdbs", java.util.List.of("kvdb_1"));
        sourceMap.put("document", documentMap);
        when(getResponse.getSourceAsMap()).thenReturn(sourceMap);

        when(this.nodeClient.get(any()))
                .thenReturn(
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
}
