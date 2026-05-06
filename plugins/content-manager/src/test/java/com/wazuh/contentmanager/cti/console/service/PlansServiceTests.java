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
package com.wazuh.contentmanager.cti.console.service;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Feature;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Mock;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link PlansService} interface and its implementation. This test suite
 * validates retrieval of CTI service subscription plans and feature information.
 *
 * <p>Tests verify successful plan retrieval, proper parsing of plan structures with associated
 * features, handling of malformed responses, and network error scenarios. Mock HTTP clients
 * simulate CTI API interactions without requiring network connectivity.
 */
public class PlansServiceTests extends OpenSearchTestCase {
    private PlansService plansService;
    @Mock private ApiClient mockClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (IllegalStateException e) {
            // Already initialized
        }

        // Mock CTI Console API Client
        this.mockClient = mock(ApiClient.class);

        // Create service and replace its client with the mock
        // Note: This creates a real ApiClient internally first, which needs to be closed
        this.plansService = new PlansServiceImpl();
        this.plansService.setClient(this.mockClient);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        // Close the service to properly shut down the HTTP client
        if (this.plansService != null) {
            this.plansService.close();
        }
    }

    /**
     * On success: - plans must not be null - plans must not be empty - a plan must contain features
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetPlansSuccess()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Mock client response upon request
        // spotless:off
        String response = """
            {
              "data": {
                "organization": {
                  "avatar": "https://acme.sl/avatar.png",
                  "name": "ACME S.L."
                },
                "plans": [
                  {
                    "name": "Wazuh Cloud",
                    "is_public": false,
                    "features": [
                      {
                        "type": "cti:catalog:consumer:vulnerabilities",
                        "name": "Vulnerabilities Pro",
                        "description": "Vulnerabilities updated as soon as they are added to the catalog",
                        "resource": "https://localhost:8080/api/v1/catalog/contexts/vulnerabilities/consumers/realtime"
                      },
                      {
                        "type": "cti:catalog:consumer:iocs",
                        "name": "Bad Guy IPs",
                        "description": "Dolor sit amet…",
                        "resource": "https://localhost:8080/api/v1/catalog/contexts/bad-guy-ips/consumers/realtime"
                      }
                    ]
                  }
                ]
              }
            }""";
        // spotless:on
        when(this.mockClient.getPlans(any(Token.class)))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        List<Plan> plans = this.plansService.getPlans(new Token("anyToken", "Bearer"));

        // plans must not be null, or empty
        Assert.assertNotNull(plans);
        Assert.assertFalse(plans.isEmpty());

        // plan must contain features
        Assert.assertFalse(plans.getFirst().getFeatures().isEmpty());
    }

    /**
     * Possible failures - CTI replies with an error - CTI unreachable in these cases, the method is
     * expected to return null.
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetPlansFailure()
            throws ExecutionException, InterruptedException, TimeoutException {
        List<Plan> plans;
        String response =
                "{\"error\": \"unauthorized_client\", \"error_description\": \"The provided token is invalid or expired\"}";

        // When CTI replies with an error code, token must be null. No exception raised
        when(this.mockClient.getPlans(any(Token.class)))
                .thenReturn(
                        SimpleHttpResponse.create(
                                400, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));
        plans = this.plansService.getPlans(new Token("anyToken", "Bearer"));
        Assert.assertNull(plans);

        // When CTI does not reply, token must be null and exceptions are raised.
        when(this.mockClient.getPlans(any(Token.class))).thenThrow(ExecutionException.class);
        plans = this.plansService.getPlans(new Token("anyToken", "Bearer"));
        Assert.assertNull(plans);
    }

    /**
     * Test getMyPlan successful retrieval. On success: - plan must not be null - plan name must match
     * the expected value - plan features must be correctly parsed
     *
     * @throws ExecutionException ignored
     * @throws InterruptedException ignored
     * @throws TimeoutException ignored
     */
    public void testGetMyPlanSuccess()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Mock client response for the /platform/environments/me endpoint
        // This endpoint returns a plan list directly under the "plans" key
        // spotless:off
        String response = """
        {
          "name": "environment-01",
          "organization": {
            "name": "Acme Corp"
          },
          "plans": [
            {
              "name": "Free Plan",
              "is_public": true,
              "features": [
                {
                  "name": "Vulnerability CVE Stream",
                  "description": "Delta updates for vulnerability entries in the Wazuh CTI catalog.",
                  "resource": "https://cti.dev.cloud.wazuh.com/api/v1/catalog/contexts/vulnerabilities_vdp/consumers/vdp_v1",
                  "type": "cti:catalog:consumer:vulnerabilities"
                }
              ]
            }
          ]
        }""";
        // spotless:on

        // Mock the call to the ApiClient method
        when(this.mockClient.getEnvironmentMe(any(Token.class)))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Token testToken = new Token("anyToken", "Bearer");
        Plan plan = ((PlansServiceImpl) this.plansService).getMyPlan(testToken);

        if (plan != null) {
            logger.info("PLAN: {}", plan.getName());
            plan.getFeatures().forEach(f -> logger.info(" - FEATURE: {} ({})", f.getName(), f.getType()));
        }

        Assert.assertNotNull(plan);

        Assert.assertNotNull("El plan no debería ser nulo", plan);
        Assert.assertEquals("Free Plan", plan.getName());
        Assert.assertTrue("El campo is_public debería ser true", plan.isPublic());

        Assert.assertFalse("La lista de features no debería estar vacía", plan.getFeatures().isEmpty());
        Feature vdp = plan.getFeature("cti:catalog:consumer:vulnerabilities");
        Assert.assertNotNull("Debería encontrar la feature de vulnerabilidades", vdp);
        Assert.assertEquals("Vulnerability CVE Stream", vdp.getName());
        Assert.assertEquals(
                "https://cti.dev.cloud.wazuh.com/api/v1/catalog/contexts/vulnerabilities_vdp/consumers/vdp_v1",
                vdp.getResource());

        // Verify the client was called with the correct token
        verify(this.mockClient, times(1)).getEnvironmentMe(testToken);
    }

    /** Test getMyPlan failure when API returns an error code. */
    public void testGetMyPlanFailure()
            throws ExecutionException, InterruptedException, TimeoutException {
        String errorResponse = "{\"errors\": {\"detail\": \"Unauthorized\"}}";

        when(this.mockClient.getEnvironmentMe(any(Token.class)))
                .thenReturn(
                        SimpleHttpResponse.create(
                                401, errorResponse.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Plan plan = ((PlansServiceImpl) this.plansService).getMyPlan(new Token("anyToken", "Bearer"));

        Assert.assertNull("Should return null on API error code", plan);
    }
}
