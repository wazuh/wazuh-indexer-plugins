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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.Assert;
import org.junit.Before;

import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the {@link RestDeleteSpaceAction} class. This test suite validates the REST API
 * endpoint responsible for resetting user spaces to their default state.
 *
 * <p>Tests verify proper validation of space parameters, deletion of SAP resources, wiping of local
 * indices, policy regeneration, and logtest state reset for testing environments.
 */
public class RestDeleteSpaceActionTests extends OpenSearchTestCase {

    private RestDeleteSpaceAction action;
    private EngineService engineService;
    private SpaceService spaceService;
    private SecurityAnalyticsService securityAnalyticsService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.engineService = mock(EngineService.class);
        this.spaceService = mock(SpaceService.class);
        this.securityAnalyticsService = mock(SecurityAnalyticsService.class);

        this.action = new RestDeleteSpaceAction(this.engineService);

        this.action.setSpaceService(this.spaceService);
        this.action.setSecurityAnalyticsService(this.securityAnalyticsService);
    }

    /**
     * Test that if an exception occurs during individual SAP resource deletions, the reset process
     * catches it and continues to delete the rest of the space successfully.
     */
    public void testDeleteSpace_SAPDeletionThrowsException_ContinuesSuccessfully() throws Exception {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of(Constants.KEY_SPACE, "draft"))
                        .build();

        Map<String, Map<String, String>> resources = new HashMap<>();
        resources.put(Constants.KEY_RULES, Map.of("rule1", "hash1"));
        when(this.spaceService.getSpaceResources("draft")).thenReturn(resources);

        doThrow(new RuntimeException("Simulated SAP error"))
                .when(this.securityAnalyticsService)
                .deleteRule(anyString(), anyBoolean());

        RestResponse response = this.action.handleRequest(request);

        // It should complete successfully despite the exception from SAP
        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.spaceService).deleteSpaceResources("draft");
    }

    /**
     * Test failure when attempting to reset the "standard" space. Expected outcome: 400 Bad Request.
     */
    public void testDeleteSpace_StandardSpace_Returns400() {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of(Constants.KEY_SPACE, "standard"))
                        .build();

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Cannot reset the 'standard' space"));
    }

    /**
     * Test failure when an invalid space identifier is provided. Expected outcome: 400 Bad Request.
     */
    public void testDeleteSpace_InvalidSpace_Returns400() {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of(Constants.KEY_SPACE, "non_existent_space"))
                        .build();

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Invalid space"));
    }

    /**
     * Test failure when a core component (like SpaceService) throws an unexpected exception. Expected
     * outcome: 500 Internal Server Error.
     */
    public void testDeleteSpace_Exception_Returns500() throws Exception {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of(Constants.KEY_SPACE, "draft"))
                        .build();

        when(this.spaceService.getSpaceResources("draft"))
                .thenThrow(new RuntimeException("Simulated catastrophic failure"));

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("Simulated catastrophic failure"));
    }
}
