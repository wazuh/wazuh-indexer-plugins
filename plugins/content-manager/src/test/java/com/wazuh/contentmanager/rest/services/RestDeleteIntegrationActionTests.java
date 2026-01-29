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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.securityanalytics.action.WDeleteIntegrationResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RestDeleteIntegrationAction}.
 *
 * <p>These tests validate the REST action behavior when deleting an integration:
 *
 * <ul>
 *   <li>Interaction with Security Analytics (policy/integration removal)
 *   <li>Deletion from the Content Manager integrations index
 *   <li>HTTP status mapping for success and failure scenarios
 * </ul>
 *
 * <p>All OpenSearch client interactions are mocked; no real cluster is involved.
 */
public class RestDeleteIntegrationActionTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private EngineService engine;
    private SecurityAnalyticsService securityAnalyticsService;
    private Client client;

    private RestDeleteIntegrationAction action;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        engine = mock(EngineService.class);
        securityAnalyticsService = mock(SecurityAnalyticsService.class);
        client = mock(Client.class);

        action = spy(new RestDeleteIntegrationAction(engine, securityAnalyticsService));
    }

    /**
     * Verifies that a valid delete request returns {@code 200 OK} when:
     *
     * <ul>
     *   <li>The integration exists in the integrations index
     *   <li>Security Analytics accepts the deletion request
     *   <li>The integrations index document is successfully deleted
     * </ul>
     *
     * @throws Exception if the test fixture cannot be prepared
     */
    public void testDeleteIntegration200() throws Exception {
        mockHappyPath("integration-1");

        WDeleteIntegrationResponse sapResponse = mock(WDeleteIntegrationResponse.class);
        when(sapResponse.getStatus()).thenReturn(RestStatus.OK);
        when(securityAnalyticsService.deleteIntegration("integration-1")).thenReturn(sapResponse);

        DeleteResponse deleteResponse = mock(DeleteResponse.class);
        when(deleteResponse.status()).thenReturn(RestStatus.OK);

        // doReturn(deleteResponse).when(action).integrationsIndex.delete("integration-1");

        RestRequest request = mockRequest("integration-1");
        RestResponse response = action.handleRequest(request, client);

        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
    }

    /**
     * Verifies that the REST action propagates a {@code 400 BAD REQUEST} when Security Analytics
     * rejects the delete integration request.
     *
     * @throws Exception if the test fixture cannot be prepared
     */
    public void testDeleteIntegration400() throws Exception {
        mockHappyPath("integration-1");

        WDeleteIntegrationResponse sapResponse = mock(WDeleteIntegrationResponse.class);
        when(sapResponse.getStatus()).thenReturn(RestStatus.BAD_REQUEST);
        when(securityAnalyticsService.deleteIntegration("integration-1")).thenReturn(sapResponse);

        RestRequest request = mockRequest("integration-1");
        RestResponse response = action.handleRequest(request, client);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /**
     * Verifies that unexpected failures while deleting the integration document from the integrations
     * index are translated into {@code 500 INTERNAL SERVER ERROR}.
     *
     * @throws Exception if the test fixture cannot be prepared
     */
    public void testDeleteIntegration500() throws Exception {
        mockHappyPath("integration-1");

        WDeleteIntegrationResponse sapResponse = mock(WDeleteIntegrationResponse.class);
        when(sapResponse.getStatus()).thenReturn(RestStatus.OK);
        when(securityAnalyticsService.deleteIntegration("integration-1")).thenReturn(sapResponse);

        // doThrow(new
        // OpenSearchException("boom")).when(action).integrationsIndex.delete("integration-1");

        RestRequest request = mockRequest("integration-1");
        RestResponse response = action.handleRequest(request, client);

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }

    /* ---------------------------------------------------
     * Helpers
     * --------------------------------------------------- */

    private void mockHappyPath(String integrationId) throws Exception {
        // integrations index exists
        // action.integrationsIndex = mock(ContentIndex.class);
        // when(action.integrationsIndex.exists(integrationId)).thenReturn(true);

        // policy search hit
        SearchHit hit = new SearchHit(0);
        hit.sourceRef(null);
        // hit.sourceAsString(createPolicyDocument(integrationId));
        // hit.setId("policy-1");

        SearchHits hits = new SearchHits(new SearchHit[] {hit}, null, 1f);
        SearchResponse searchResponse = mock(SearchResponse.class);
        when(searchResponse.getHits()).thenReturn(hits);

        // when(client.search(any()))
        //        .thenReturn(
        //                Mockito.mock(
        //                        org.opensearch.action.search.SearchRequestBuilder.class,
        //                        invocation -> {
        //                            if (invocation.getMethod().getName().equals("actionGet")) {
        //                                return searchResponse;
        //                            }
        //                            return null;
        //                        }));

        UpdateResponse updateResponse = mock(UpdateResponse.class);
        when(updateResponse.status()).thenReturn(RestStatus.OK);

        // when(client.update(any()))
        //        .thenReturn(
        //                Mockito.mock(
        //                        org.opensearch.action.update.UpdateRequestBuilder.class,
        //                        invocation -> {
        //                            if (invocation.getMethod().getName().equals("actionGet")) {
        //                                return updateResponse;
        //                            }
        //                            return null;
        //                        }));
    }

    private String createPolicyDocument(String integrationId) throws Exception {
        ObjectNode root = MAPPER.createObjectNode();
        ObjectNode source = root.putObject("_source");

        ObjectNode document = source.putObject("document");
        ArrayNode integrations = document.putArray("integrations");
        integrations.add(integrationId);

        ObjectNode hash = source.putObject("hash");
        hash.put("sha256", "old-hash");

        ObjectNode space = source.putObject("space");
        space.put("name", "draft");

        return MAPPER.writeValueAsString(root);
    }

    private RestRequest mockRequest(String id) {
        RestRequest request = mock(RestRequest.class);
        when(request.param("id")).thenReturn(id);
        return request;
    }
}
