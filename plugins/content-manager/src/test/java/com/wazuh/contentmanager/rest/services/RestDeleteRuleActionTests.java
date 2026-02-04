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
package com.wazuh.contentmanager.rest.services;

import org.opensearch.action.get.GetResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.io.IOException;
import java.util.Map;

import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.securityanalytics.action.WDeleteCustomRuleAction;
import com.wazuh.securityanalytics.action.WDeleteCustomRuleRequest;
import com.wazuh.securityanalytics.action.WDeleteRuleResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestDeleteRuleAction} class. This test suite validates the REST API
 * endpoint responsible for deleting new CTI Rules.
 *
 * <p>Tests verify Rule delete requests, proper handling of Rule data, and appropriate HTTP response
 * codes for successful Rule delete errors.
 */
public class RestDeleteRuleActionTests extends OpenSearchTestCase {

    private RestDeleteRuleAction action;
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
        PluginSettings.getInstance(Settings.EMPTY);
        this.client = mock(Client.class);
        this.action = new RestDeleteRuleAction();
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when the
     * request is complete. The expected response is: {200, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteRule200() throws IOException {
        // Arrange
        String ruleId = "1b5a5cfb-a5fc-4db7-b5cc-bf9093a04121";

        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("id", ruleId))
                        .build();

        // Mock client with RETURNS_DEEP_STUBS for chained calls
        this.client = mock(Client.class, RETURNS_DEEP_STUBS);

        // Mock draft space validation
        GetResponse ruleGetResponse = mock(GetResponse.class);
        when(ruleGetResponse.isExists()).thenReturn(true);
        java.util.Map<String, Object> ruleSource = new java.util.HashMap<>();
        java.util.Map<String, Object> ruleSpace = new java.util.HashMap<>();
        ruleSpace.put("name", "draft");
        ruleSource.put("space", ruleSpace);
        when(ruleGetResponse.getSourceAsMap()).thenReturn(ruleSource);
        when(this.client.prepareGet(anyString(), anyString()).get()).thenReturn(ruleGetResponse);

        // Mock SAP delete
        this.mockSapDelete(ruleId);

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.OK.getStatus(), response.getStatus());

        verify(this.client)
                .execute(eq(WDeleteCustomRuleAction.INSTANCE), any(WDeleteCustomRuleRequest.class));
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when the rule
     * has not been deleted (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteRule400_MissingId() throws IOException {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        RestResponse response = this.action.handleRequest(request, this.client);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /**
     * Test the {@link RestDeleteRuleAction#handleRequest(RestRequest, Client)} method when an
     * unexpected error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteRule500() throws IOException {
        // Mock
        RestRequest request = mock(RestRequest.class);

        // Act
        RestResponse response = this.action.handleRequest(request, this.client);

        // Assert
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }

    /**
     * Mocks the successful execution of the Security Analytics Plugin (SAP) delete rule action.
     *
     * @param ruleId The ID of the rule expected to be deleted.
     */
    private void mockSapDelete(String ruleId) {
        ActionFuture<WDeleteRuleResponse> sapFuture = mock(ActionFuture.class);
        when(sapFuture.actionGet()).thenReturn(new WDeleteRuleResponse(ruleId, 1L, RestStatus.OK));
        doReturn(sapFuture)
                .when(this.client)
                .execute(eq(WDeleteCustomRuleAction.INSTANCE), any(WDeleteCustomRuleRequest.class));
    }
}
