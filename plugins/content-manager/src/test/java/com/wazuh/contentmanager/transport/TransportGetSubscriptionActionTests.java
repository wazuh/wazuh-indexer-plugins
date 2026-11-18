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
package com.wazuh.contentmanager.transport;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.action.GetSubscriptionRequest;
import com.wazuh.contentmanager.action.GetSubscriptionResponse;
import com.wazuh.contentmanager.cti.catalog.index.CredentialsIndex;
import com.wazuh.contentmanager.cti.catalog.service.SubscriptionServiceImpl;
import com.wazuh.contentmanager.cti.console.EnvironmentFixtures;
import com.wazuh.contentmanager.cti.console.client.ApiClient;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.CtiConsoleUnavailableException;
import com.wazuh.contentmanager.cti.console.service.PlansServiceImpl;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.Mockito.*;

public class TransportGetSubscriptionActionTests extends OpenSearchTestCase {
    private SubscriptionServiceImpl subscriptionService;
    private TransportGetSubscriptionAction action;

    /** The real plan lookup of the tests that build the action over it, closed after each test. */
    private PlansServiceImpl plansService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);
        this.subscriptionService = mock(SubscriptionServiceImpl.class);
        this.action =
                new TransportGetSubscriptionAction(
                        mock(TransportService.class), mock(ActionFilters.class), this.subscriptionService);
    }

    @After
    public void tearDown() throws Exception {
        if (this.plansService != null) {
            this.plansService.close();
        }
        clearPluginSettingsInstance();
        super.tearDown();
    }

    private static String toJson(GetSubscriptionResponse response) {
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            response.toXContent(builder, ToXContent.EMPTY_PARAMS);
            return BytesReference.bytes(builder).utf8ToString();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    @SuppressWarnings("unchecked")
    public void testDoExecute_SuccessWithPlan() throws Exception {
        Plan plan = mock(Plan.class);
        when(plan.getName()).thenReturn("premium");
        when(plan.isPublic()).thenReturn(false);
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(0);
                            asyncListener.onResponse(plan);
                            return null;
                        })
                .when(this.subscriptionService)
                .getPlan(any(ActionListener.class));

        GetSubscriptionRequest request = new GetSubscriptionRequest();

        ActionListener<GetSubscriptionResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    return true;
                                }));
    }

    @SuppressWarnings("unchecked")
    public void testDoExecute_SuccessNullPlan() throws Exception {
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(0);
                            asyncListener.onResponse(null);
                            return null;
                        })
                .when(this.subscriptionService)
                .getPlan(any(ActionListener.class));

        GetSubscriptionRequest request = new GetSubscriptionRequest();

        ActionListener<GetSubscriptionResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    return true;
                                }));
    }

    /** A failed plan lookup is reported as 502 with a fixed message, not as a plan. */
    @SuppressWarnings("unchecked")
    public void testDoExecute_PlanUnavailable_Returns502() throws Exception {
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(0);
                            asyncListener.onFailure(
                                    new CtiConsoleUnavailableException(
                                            "The CTI Console answered status 503 to the plan lookup."));
                            return null;
                        })
                .when(this.subscriptionService)
                .getPlan(any(ActionListener.class));

        ActionListener<GetSubscriptionResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), new GetSubscriptionRequest(), listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.BAD_GATEWAY, response.getStatus());
                                    Assert.assertEquals(
                                            "{\"message\":\""
                                                    + Constants.E_502_CTI_PLAN_UNAVAILABLE
                                                    + "\",\"status\":502}",
                                            toJson(response));
                                    return true;
                                }));
    }

    @SuppressWarnings("unchecked")
    public void testDoExecute_Exception() throws Exception {
        doAnswer(
                        invocation -> {
                            ActionListener<Plan> asyncListener = invocation.getArgument(0);
                            asyncListener.onFailure(new RuntimeException("Service error"));
                            return null;
                        })
                .when(this.subscriptionService)
                .getPlan(any(ActionListener.class));

        GetSubscriptionRequest request = new GetSubscriptionRequest();

        ActionListener<GetSubscriptionResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.getStatus());
                                    return true;
                                }));
    }

    /** The answer for an unregistered instance, and for one whose token was just rejected. */
    private static final String OPEN_PLAN_RESPONSE =
            "{\"message\":{\"plan\":{\"name\":\"Open\",\"is_public\":true},\"is_registered\":false},"
                    + "\"status\":200}";

    private static final String OPEN_CATALOG_PLANS =
            "{\"plans\": [{\"name\": \"Open\", \"is_public\": true}]}";

    /**
     * Builds the action over the real token handling and plan lookup, with only the CTI Console HTTP
     * client and the credentials index mocked.
     */
    private TransportGetSubscriptionAction actionOverConsole(
            ApiClient client, CredentialsIndex credentialsIndex) {
        this.plansService = new PlansServiceImpl();
        this.plansService.setClient(client);
        return new TransportGetSubscriptionAction(
                mock(TransportService.class),
                mock(ActionFilters.class),
                new SubscriptionServiceImpl(this.plansService, credentialsIndex, true));
    }

    @SuppressWarnings("unchecked")
    private static void stubEnvironmentMe(ApiClient client, int status, String body) {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<SimpleHttpResponse>>getArgument(1)
                                    .onResponse(
                                            SimpleHttpResponse.create(status, body, ContentType.APPLICATION_JSON));
                            return null;
                        })
                .when(client)
                .getEnvironmentMe(any(Token.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    private static void stubCatalogPlans(ApiClient client) {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<SimpleHttpResponse>>getArgument(0)
                                    .onResponse(
                                            SimpleHttpResponse.create(
                                                    200, OPEN_CATALOG_PLANS, ContentType.APPLICATION_JSON));
                            return null;
                        })
                .when(client)
                .getCatalogPlans(any(ActionListener.class));
    }

    private static String execute(TransportGetSubscriptionAction action) {
        AtomicReference<GetSubscriptionResponse> response = new AtomicReference<>();
        action.doExecute(
                mock(Task.class),
                new GetSubscriptionRequest(),
                ActionListener.wrap(response::set, e -> Assert.fail("unexpected failure: " + e)));
        Assert.assertNotNull("no response", response.get());
        return TransportGetSubscriptionActionTests.toJson(response.get());
    }

    /**
     * A registered instance gets the CTI Console environment under {@code message.environment}, as
     * received: field order, {@code null} values, dates and the unknown {@code limits} field are
     * kept, and the existing fields do not change.
     */
    public void testRegisteredInstanceGetsTheEnvironmentAsReceived() throws Exception {
        PluginSettings.getInstance().setAccessToken("valid-token");
        ApiClient client = mock(ApiClient.class);
        TransportGetSubscriptionActionTests.stubEnvironmentMe(
                client, 200, EnvironmentFixtures.REGISTERED);

        String json =
                TransportGetSubscriptionActionTests.execute(
                        this.actionOverConsole(client, mock(CredentialsIndex.class)));

        Assert.assertEquals(
                "{\"message\":{\"plan\":{\"name\":\"Pro\",\"is_public\":false},\"is_registered\":true,"
                        + "\"environment\":"
                        + new ObjectMapper().readTree(EnvironmentFixtures.REGISTERED).toString()
                        + "},\"status\":200}",
                json);
        verify(client, times(1)).getEnvironmentMe(any(Token.class), any(ActionListener.class));
        verify(client, never()).getCatalogPlans(any(ActionListener.class));
    }

    /** An unregistered instance has no environment: the answer is the same as before. */
    @SuppressWarnings("unchecked")
    public void testUnregisteredInstanceHasNoEnvironment() {
        ApiClient client = mock(ApiClient.class);
        TransportGetSubscriptionActionTests.stubCatalogPlans(client);
        CredentialsIndex credentialsIndex = mock(CredentialsIndex.class);
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Boolean>>getArgument(0).onResponse(false);
                            return null;
                        })
                .when(credentialsIndex)
                .exists(any(ActionListener.class));

        String json =
                TransportGetSubscriptionActionTests.execute(
                        this.actionOverConsole(client, credentialsIndex));

        Assert.assertEquals(OPEN_PLAN_RESPONSE, json);
        verify(client, never()).getEnvironmentMe(any(Token.class), any(ActionListener.class));
    }

    /**
     * A rejected token is cleared and the public plan is reported as before, without the environment
     * of the rejected registration.
     */
    @SuppressWarnings("unchecked")
    public void testRejectedTokenFallsBackWithoutEnvironment() {
        PluginSettings.getInstance().setAccessToken("revoked-token");
        ApiClient client = mock(ApiClient.class);
        TransportGetSubscriptionActionTests.stubEnvironmentMe(
                client, 401, "{\"error\": \"unauthorized_client\"}");
        TransportGetSubscriptionActionTests.stubCatalogPlans(client);
        CredentialsIndex credentialsIndex = mock(CredentialsIndex.class);
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<DeleteResponse>>getArgument(0).onResponse(null);
                            return null;
                        })
                .when(credentialsIndex)
                .deleteDocument(any(ActionListener.class));

        String json =
                TransportGetSubscriptionActionTests.execute(
                        this.actionOverConsole(client, credentialsIndex));

        Assert.assertEquals(OPEN_PLAN_RESPONSE, json);
        verify(credentialsIndex, times(1)).deleteDocument(any(ActionListener.class));
        Assert.assertNull(PluginSettings.getInstance().getAccessToken());
    }

    /**
     * An unusable CTI Console answer is the same 502 as before and keeps the token, even when the
     * answer is valid JSON: the environment is passed through only with a plan.
     */
    public void testUnusableConsoleAnswerIsStill502() {
        for (String[] answer :
                new String[][] {
                    {"503", "{\"error\": \"unavailable\"}"},
                    {"200", "{\"name\": \"environment-01\", \"plans\": []}"},
                    {"200", "{\"name\": \"environment-01\"}"}
                }) {
            PluginSettings.getInstance().setAccessToken("valid-token");
            ApiClient client = mock(ApiClient.class);
            TransportGetSubscriptionActionTests.stubEnvironmentMe(
                    client, Integer.parseInt(answer[0]), answer[1]);

            String json =
                    TransportGetSubscriptionActionTests.execute(
                            this.actionOverConsole(client, mock(CredentialsIndex.class)));
            this.plansService.close();

            Assert.assertEquals(
                    "{\"message\":\"" + Constants.E_502_CTI_PLAN_UNAVAILABLE + "\",\"status\":502}", json);
            Assert.assertEquals("valid-token", PluginSettings.getInstance().getAccessToken());
        }
    }

    /**
     * Answers that a lenient JSON parse accepts gave a plan before and still do, with the environment
     * as parsed, instead of failing when the environment is written: a repeated field keeps its last
     * value, and text after the object is ignored.
     */
    public void testLenientConsoleAnswerStillGivesThePlan() throws Exception {
        String plans = "\"plans\": [{\"name\": \"Pro\", \"is_public\": false}]";
        for (String[] answer :
                new String[][] {
                    {
                        "{\"name\": \"old\", \"name\": \"environment-01\", " + plans + "}",
                        "{\"name\":\"environment-01\",\"plans\":[{\"name\":\"Pro\",\"is_public\":false}]}"
                    },
                    {
                        "{\"name\": \"environment-01\", " + plans + "} trailing",
                        "{\"name\":\"environment-01\",\"plans\":[{\"name\":\"Pro\",\"is_public\":false}]}"
                    }
                }) {
            PluginSettings.getInstance().setAccessToken("valid-token");
            ApiClient client = mock(ApiClient.class);
            TransportGetSubscriptionActionTests.stubEnvironmentMe(client, 200, answer[0]);

            String json =
                    TransportGetSubscriptionActionTests.execute(
                            this.actionOverConsole(client, mock(CredentialsIndex.class)));
            this.plansService.close();

            Assert.assertEquals(
                    "{\"message\":{\"plan\":{\"name\":\"Pro\",\"is_public\":false},\"is_registered\":true,"
                            + "\"environment\":"
                            + answer[1]
                            + "},\"status\":200}",
                    json);
        }
    }

    /**
     * An instance unregistered while its plan lookup was in flight is reported unregistered, so the
     * environment of the removed registration is left out.
     */
    @SuppressWarnings("unchecked")
    public void testInstanceUnregisteredDuringLookupHasNoEnvironment() {
        PluginSettings.getInstance().setAccessToken("valid-token");
        ApiClient client = mock(ApiClient.class);
        doAnswer(
                        invocation -> {
                            PluginSettings.getInstance().setAccessToken(null);
                            invocation
                                    .<ActionListener<SimpleHttpResponse>>getArgument(1)
                                    .onResponse(
                                            SimpleHttpResponse.create(
                                                    200, EnvironmentFixtures.REGISTERED, ContentType.APPLICATION_JSON));
                            return null;
                        })
                .when(client)
                .getEnvironmentMe(any(Token.class), any(ActionListener.class));

        String json =
                TransportGetSubscriptionActionTests.execute(
                        this.actionOverConsole(client, mock(CredentialsIndex.class)));

        Assert.assertEquals(
                "{\"message\":{\"plan\":{\"name\":\"Pro\",\"is_public\":false},\"is_registered\":false},"
                        + "\"status\":200}",
                json);
    }
}
