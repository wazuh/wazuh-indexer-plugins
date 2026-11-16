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

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestChannel;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.DeleteSubscriptionRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

public class RestDeleteSubscriptionActionTests extends OpenSearchTestCase {
    private RestDeleteSubscriptionAction action;
    private CapturingNodeClient<DeleteSubscriptionRequest> client;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.action = new RestDeleteSubscriptionAction();
        this.client = new CapturingNodeClient<>(getTestName());
    }

    @After
    @Override
    public void tearDown() throws Exception {
        this.client.close();
        super.tearDown();
    }

    // --- route metadata ----------------------------------------------------------

    public void testRouteMethod() {
        Assert.assertEquals(1, this.action.routes().size());
        Assert.assertEquals(RestRequest.Method.DELETE, this.action.routes().get(0).getMethod());
    }

    public void testRoutePath() {
        Assert.assertEquals(PluginSettings.SUBSCRIPTION_URI, this.action.routes().get(0).getPath());
    }

    public void testName() {
        Assert.assertEquals("content_manager_subscription_delete", this.action.getName());
    }

    // --- dispatch: which transport request is built -------------------------------

    public void testDispatch_withoutParameter_deletes() throws Exception {
        dispatch(Map.of(), null);

        Assert.assertNotNull(this.client.captured);
        Assert.assertFalse(this.client.captured.isPermissionCheckOnly());
    }

    public void testDispatch_parameterFalse_deletes() throws Exception {
        dispatch(Map.of("perform_permission_check", "false"), null);

        Assert.assertNotNull(this.client.captured);
        Assert.assertFalse(this.client.captured.isPermissionCheckOnly());
    }

    public void testDispatch_parameterTrue_flagsTheRequest() throws Exception {
        dispatch(Map.of("perform_permission_check", "true"), null);

        Assert.assertNotNull(this.client.captured);
        Assert.assertTrue(this.client.captured.isPermissionCheckOnly());
    }

    /** An empty value means true, per the OpenSearch boolean-parameter contract. */
    public void testDispatch_parameterEmptyValue_flagsTheRequest() throws Exception {
        dispatch(Map.of("perform_permission_check", ""), null);

        Assert.assertNotNull(this.client.captured);
        Assert.assertTrue(this.client.captured.isPermissionCheckOnly());
    }

    // --- response rendering ------------------------------------------------------

    /**
     * The security plugin answers with its own {@code PermissionCheckResponse}, which is not a {@link
     * MessageStatusResponse}. Its body must be passed through unchanged, not fail with a 500.
     */
    public void testResponse_securityPluginDenies_isPassedThroughUnchanged() throws Exception {
        FakeRestChannel channel =
                dispatch(
                        Map.of("perform_permission_check", "true"),
                        new PermissionCheckResponseDouble(
                                false, Set.of("cluster:admin/content_manager/subscription/delete")));

        RestResponse response = channel.capturedResponse();
        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertEquals(
                "{\"accessAllowed\":false,"
                        + "\"missingPrivileges\":[\"cluster:admin/content_manager/subscription/delete\"]}",
                response.content().utf8ToString());
    }

    public void testResponse_securityPluginAllows_isPassedThroughUnchanged() throws Exception {
        FakeRestChannel channel =
                dispatch(
                        Map.of("perform_permission_check", "true"),
                        new PermissionCheckResponseDouble(true, Set.of()));

        RestResponse response = channel.capturedResponse();
        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertEquals(
                "{\"accessAllowed\":true,\"missingPrivileges\":[]}", response.content().utf8ToString());
    }

    /**
     * Security disabled: no filter intercepts, so the transport action's own fallback comes back. The
     * handler must still answer the native permission-check body.
     */
    public void testResponse_securityDisabledFallback_rendersAccessAllowed() throws Exception {
        FakeRestChannel channel =
                dispatch(
                        Map.of("perform_permission_check", "true"),
                        new MessageStatusResponse(Constants.S_200_PERMISSION_CHECK_ALLOWED, RestStatus.OK));

        RestResponse response = channel.capturedResponse();
        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertEquals(
                "{\"accessAllowed\":true,\"missingPrivileges\":[]}", response.content().utf8ToString());
    }

    public void testResponse_deletion_rendersMessageAndStatus() throws Exception {
        FakeRestChannel channel =
                dispatch(Map.of(), new MessageStatusResponse("Credentials removed", RestStatus.OK));

        RestResponse response = channel.capturedResponse();
        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertEquals(
                "{\"message\":\"Credentials removed\",\"status\":200}", response.content().utf8ToString());
    }

    public void testResponse_deletionFailure_rendersMessageAndStatus() throws Exception {
        FakeRestChannel channel =
                dispatch(
                        Map.of(),
                        new MessageStatusResponse("Unexpected failure", RestStatus.INTERNAL_SERVER_ERROR));

        RestResponse response = channel.capturedResponse();
        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
        Assert.assertEquals(
                "{\"message\":\"Unexpected failure\",\"status\":500}", response.content().utf8ToString());
    }

    // --- helpers -----------------------------------------------------------------

    /**
     * Runs the handler end to end.
     *
     * @param params query parameters
     * @param response what the transport layer answers, or null to answer nothing
     * @return the channel the response was written to
     */
    private FakeRestChannel dispatch(Map<String, String> params, ActionResponse response)
            throws Exception {
        this.client.response = response;

        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withMethod(RestRequest.Method.DELETE)
                        .withPath(PluginSettings.SUBSCRIPTION_URI)
                        .withParams(new HashMap<>(params))
                        .build();
        FakeRestChannel channel = new FakeRestChannel(request, true, 1);
        this.action.handleRequest(request, channel, this.client);
        return channel;
    }
}
