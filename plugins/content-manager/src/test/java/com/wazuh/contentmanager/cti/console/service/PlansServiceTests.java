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
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Feature;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Mock;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
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

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field f = PluginSettings.class.getDeclaredField("INSTANCE");
        f.setAccessible(true);
        f.set(null, null);
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);
        this.mockClient = mock(ApiClient.class);
        this.plansService = new PlansServiceImpl();
        this.plansService.setClient(this.mockClient);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        if (this.plansService != null) {
            this.plansService.close();
        }
        clearPluginSettingsInstance();
        super.tearDown();
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
    public void testGetMyPlanSuccess() throws Exception {
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

    /** A 401 is the only answer that means the token was rejected. */
    public void testGetMyPlanUnauthorizedThrowsTokenRejected()
            throws ExecutionException, InterruptedException, TimeoutException {
        String errorResponse = "{\"errors\": {\"detail\": \"Unauthorized\"}}";

        when(this.mockClient.getEnvironmentMe(any(Token.class)))
                .thenReturn(
                        SimpleHttpResponse.create(
                                401, errorResponse.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        expectThrows(
                TokenRejectedException.class,
                () -> ((PlansServiceImpl) this.plansService).getMyPlan(new Token("anyToken", "Bearer")));
    }

    /** Any other error status says nothing about the token. */
    public void testGetMyPlanErrorStatusThrowsPlanUnavailable()
            throws ExecutionException, InterruptedException, TimeoutException {
        for (int status : new int[] {403, 404, 429, 500, 502, 503}) {
            when(this.mockClient.getEnvironmentMe(any(Token.class)))
                    .thenReturn(
                            SimpleHttpResponse.create(
                                    status,
                                    "{\"error\": \"x\"}".getBytes(StandardCharsets.UTF_8),
                                    ContentType.APPLICATION_JSON));

            CtiConsoleUnavailableException e =
                    expectThrows(
                            CtiConsoleUnavailableException.class,
                            () -> ((PlansServiceImpl) this.plansService).getMyPlan(new Token("t", "Bearer")));
            Assert.assertTrue(e.getMessage(), e.getMessage().contains(String.valueOf(status)));
        }
    }

    /** A request that times out or cannot connect says nothing about the token. */
    public void testGetMyPlanRequestFailureThrowsPlanUnavailable()
            throws ExecutionException, InterruptedException, TimeoutException {
        when(this.mockClient.getEnvironmentMe(any(Token.class)))
                .thenThrow(new TimeoutException("5 SECONDS"))
                .thenThrow(new ExecutionException(new java.net.ConnectException("Connection refused")));

        CtiConsoleUnavailableException timeout =
                expectThrows(
                        CtiConsoleUnavailableException.class,
                        () -> ((PlansServiceImpl) this.plansService).getMyPlan(new Token("t", "Bearer")));
        Assert.assertTrue(timeout.getCause() instanceof TimeoutException);
        CtiConsoleUnavailableException refused =
                expectThrows(
                        CtiConsoleUnavailableException.class,
                        () -> ((PlansServiceImpl) this.plansService).getMyPlan(new Token("t", "Bearer")));
        Assert.assertTrue(refused.getCause() instanceof ExecutionException);
    }

    /** A 200 that cannot be parsed or lists no plan is unusable, not a rejection. */
    public void testGetMyPlanUnusableResponseThrowsPlanUnavailable()
            throws ExecutionException, InterruptedException, TimeoutException {
        for (String body : new String[] {"not json", "{}", "{\"plans\": []}"}) {
            when(this.mockClient.getEnvironmentMe(any(Token.class)))
                    .thenReturn(
                            SimpleHttpResponse.create(
                                    200, body.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

            expectThrows(
                    CtiConsoleUnavailableException.class,
                    () -> ((PlansServiceImpl) this.plansService).getMyPlan(new Token("t", "Bearer")));
        }
    }

    /** Async getMyPlan: 401 fails the listener with TokenRejectedException. */
    public void testGetMyPlanAsyncUnauthorizedFailsWithTokenRejected() {
        this.stubAsyncEnvironmentMe(SimpleHttpResponse.create(401, "{}", ContentType.APPLICATION_JSON));

        Assert.assertTrue(this.getMyPlanAsyncFailure() instanceof TokenRejectedException);
    }

    /** Async getMyPlan: a 503 fails the listener with CtiConsoleUnavailableException. */
    public void testGetMyPlanAsyncErrorStatusFailsWithPlanUnavailable() {
        this.stubAsyncEnvironmentMe(SimpleHttpResponse.create(503, "{}", ContentType.APPLICATION_JSON));

        Assert.assertTrue(this.getMyPlanAsyncFailure() instanceof CtiConsoleUnavailableException);
    }

    /**
     * Async getMyPlan: a transport failure fails the listener with CtiConsoleUnavailableException.
     */
    @SuppressWarnings("unchecked")
    public void testGetMyPlanAsyncRequestFailureFailsWithPlanUnavailable() {
        java.net.ConnectException cause = new java.net.ConnectException("Connection refused");
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<SimpleHttpResponse>>getArgument(1).onFailure(cause);
                            return null;
                        })
                .when(this.mockClient)
                .getEnvironmentMe(any(Token.class), any(ActionListener.class));

        Exception failure = this.getMyPlanAsyncFailure();
        Assert.assertTrue(failure instanceof CtiConsoleUnavailableException);
        Assert.assertSame(cause, failure.getCause());
    }

    /** Async getMyPlan: a 200 with a plan answers the listener with it. */
    public void testGetMyPlanAsyncSuccess() {
        this.stubAsyncEnvironmentMe(
                SimpleHttpResponse.create(
                        200,
                        "{\"plans\": [{\"name\": \"Premium Plan\", \"is_public\": false}]}",
                        ContentType.APPLICATION_JSON));
        AtomicReference<Plan> plan = new AtomicReference<>();

        this.plansService.getMyPlan(
                new Token("t", "Bearer"),
                ActionListener.wrap(plan::set, e -> fail("unexpected failure: " + e)));

        Assert.assertEquals("Premium Plan", plan.get().getName());
    }

    @SuppressWarnings("unchecked")
    private void stubAsyncEnvironmentMe(SimpleHttpResponse response) {
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<SimpleHttpResponse>>getArgument(1).onResponse(response);
                            return null;
                        })
                .when(this.mockClient)
                .getEnvironmentMe(any(Token.class), any(ActionListener.class));
    }

    private Exception getMyPlanAsyncFailure() {
        AtomicReference<Exception> failure = new AtomicReference<>();
        this.plansService.getMyPlan(
                new Token("t", "Bearer"),
                ActionListener.wrap(p -> fail("expected a failure, got plan " + p), failure::set));
        Assert.assertNotNull("listener was not failed", failure.get());
        return failure.get();
    }

    /** getPlan() when accessToken is set must delegate to getMyPlan(). */
    public void testGetPlanWhenRegistered() throws Exception {
        PluginSettings.getInstance().setAccessToken("test-bearer-token");

        // spotless:off
        String response = """
            {
              "name": "env-01",
              "organization": { "name": "Acme" },
              "plans": [
                { "name": "Premium Plan", "is_public": false, "features": [] }
              ]
            }""";
        // spotless:on
        when(this.mockClient.getEnvironmentMe(any(Token.class)))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Plan plan = this.plansService.getPlan();

        Assert.assertNotNull(plan);
        Assert.assertEquals("Premium Plan", plan.getName());
        verify(this.mockClient, times(1)).getEnvironmentMe(any(Token.class));
        verify(this.mockClient, times(0)).getCatalogPlans();
    }

    /** getPlan() when accessToken is null must delegate to getPublicPlan(). */
    public void testGetPlanWhenUnregistered() throws Exception {
        // accessToken is null by default after setUp()

        // spotless:off
        String response = """
            {
              "plans": [
                { "name": "Free", "is_public": true, "features": [] }
              ]
            }""";
        // spotless:on
        when(this.mockClient.getCatalogPlans())
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, response.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        Plan plan = this.plansService.getPlan();

        Assert.assertNotNull(plan);
        Assert.assertTrue(plan.isPublic());
        verify(this.mockClient, times(1)).getCatalogPlans();
        verify(this.mockClient, times(0)).getEnvironmentMe(any(Token.class));
    }
}
