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
import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;
import org.mockito.Mock;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link PlansService} interface and its implementation. This test suite
 * validates retrieval of CTI service subscription plans and product information.
 *
 * <p>Tests verify successful plan retrieval, proper parsing of plan structures with associated
 * products, handling of malformed responses, and network error scenarios. Mock HTTP clients
 * simulate CTI API interactions without requiring network connectivity.
 */
public class PlansServiceTests extends OpenSearchTestCase {
    private PlansService plansService;
    @Mock private ApiClient mockClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

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
     * On success: - plans must not be null - plans must not be empty - a plan must contain products
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
                    "description": "Managed instances in AWS by Wazuh's professional staf that…",
                    "products": [
                      {
                        "identifier": "assistance-24h",
                        "type": "cloud:assistance:wazuh",
                        "name": "Technical assistance 24h",
                        "email": "cloud@wazuh.com",
                        "phone": "+34 123 456 789"
                      },
                      {
                        "identifier": "vulnerabilities-pro",
                        "type": "catalog:consumer:vulnerabilities",
                        "name": "Vulnerabilities Pro",
                        "description": "Vulnerabilities updated as soon as they are added to the catalog",
                        "resource": "https://localhost:8080/api/v1/catalog/plans/pro/contexts/vulnerabilities/consumer/realtime"
                      },
                      {
                        "identifier": "bad-guy-ips-pro",
                        "type": "catalog:consumer:iocs",
                        "name": "Bad Guy IPs",
                        "description": "Dolor sit amet…",
                        "resource": "https://localhost:8080/api/v1/catalog/plans/pro/contexts/bad-guy-ips/consumer/realtime"
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

        // plan must contain products
        Assert.assertFalse(plans.getFirst().getProducts().isEmpty());
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
}
