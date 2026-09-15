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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.common.xcontent.StatusToXContentObject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.client.NoOpNodeClient;
import org.opensearch.test.rest.FakeRestChannel;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.IndexSubscriptionRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

public class RestPostSubscriptionActionTests extends OpenSearchTestCase {
    private RestPostSubscriptionAction action;
    private CapturingNodeClient client;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.action = new RestPostSubscriptionAction();
        this.client = new CapturingNodeClient(getTestName());
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
        Assert.assertEquals(RestRequest.Method.POST, this.action.routes().get(0).getMethod());
    }

    public void testRoutePath() {
        Assert.assertEquals(PluginSettings.SUBSCRIPTION_URI, this.action.routes().get(0).getPath());
    }

    public void testName() {
        Assert.assertEquals("content_manager_subscription_post", this.action.getName());
    }

    // --- dispatch: which transport request is built -------------------------------

    public void testDispatch_withoutParameter_parsesBodyAndRegisters() throws Exception {
        dispatch(Map.of(), "{\"access_token\":\"a-token\"}", null);

        IndexSubscriptionRequest dispatched = this.client.captured;
        Assert.assertNotNull(dispatched);
        Assert.assertFalse(dispatched.isPermissionCheckOnly());
        Assert.assertEquals("a-token", dispatched.getToken());
    }

    public void testDispatch_parameterFalse_parsesBodyAndRegisters() throws Exception {
        dispatch(Map.of("perform_permission_check", "false"), "{\"access_token\":\"a-token\"}", null);

        IndexSubscriptionRequest dispatched = this.client.captured;
        Assert.assertNotNull(dispatched);
        Assert.assertFalse(dispatched.isPermissionCheckOnly());
        Assert.assertEquals("a-token", dispatched.getToken());
    }

    /** No body is read in check mode: the request carries no content at all here. */
    public void testDispatch_parameterTrue_readsNoBodyAndFlagsTheRequest() throws Exception {
        dispatch(Map.of("perform_permission_check", "true"), null, null);

        IndexSubscriptionRequest dispatched = this.client.captured;
        Assert.assertNotNull(dispatched);
        Assert.assertTrue(dispatched.isPermissionCheckOnly());
        Assert.assertNull(dispatched.getToken());
    }

    /** An empty value means true, per the OpenSearch boolean-parameter contract. */
    public void testDispatch_parameterEmptyValue_flagsTheRequest() throws Exception {
        dispatch(Map.of("perform_permission_check", ""), null, null);

        Assert.assertNotNull(this.client.captured);
        Assert.assertTrue(this.client.captured.isPermissionCheckOnly());
    }

    /** A body sent in check mode is ignored rather than parsed. */
    public void testDispatch_parameterTrueWithBody_ignoresTheBody() throws Exception {
        dispatch(Map.of("perform_permission_check", "true"), "{\"access_token\":\"a-token\"}", null);

        Assert.assertNotNull(this.client.captured);
        Assert.assertTrue(this.client.captured.isPermissionCheckOnly());
        Assert.assertNull(this.client.captured.getToken());
    }

    // --- response rendering ------------------------------------------------------

    /**
     * The regression this whole change is about: the security plugin answers with its own {@code
     * PermissionCheckResponse}, which is not a {@link MessageStatusResponse}. A listener typed over
     * the concrete class threw {@code ClassCastException} and produced a 500; the body must now be
     * passed through unchanged.
     */
    public void testResponse_securityPluginAnswer_isPassedThroughUnchanged() throws Exception {
        FakeRestChannel channel =
                dispatch(
                        Map.of("perform_permission_check", "true"),
                        null,
                        new PermissionCheckResponseDouble(
                                false, Set.of("cluster:admin/content_manager/subscription/create")));

        RestResponse response = channel.capturedResponse();
        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertEquals(
                "{\"accessAllowed\":false,"
                        + "\"missingPrivileges\":[\"cluster:admin/content_manager/subscription/create\"]}",
                response.content().utf8ToString());
    }

    public void testResponse_securityPluginAllows_isPassedThroughUnchanged() throws Exception {
        FakeRestChannel channel =
                dispatch(
                        Map.of("perform_permission_check", "true"),
                        null,
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
                        null,
                        new MessageStatusResponse(Constants.S_200_PERMISSION_CHECK_ALLOWED, RestStatus.OK));

        RestResponse response = channel.capturedResponse();
        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertEquals(
                "{\"accessAllowed\":true,\"missingPrivileges\":[]}", response.content().utf8ToString());
    }

    public void testResponse_registration_rendersMessageAndStatus() throws Exception {
        FakeRestChannel channel =
                dispatch(
                        Map.of(),
                        "{\"access_token\":\"a-token\"}",
                        new MessageStatusResponse(Constants.S_201_ACCESS_TOKEN_RECEIVED, RestStatus.CREATED));

        RestResponse response = channel.capturedResponse();
        Assert.assertEquals(RestStatus.CREATED, response.status());
        Assert.assertEquals(
                "{\"message\":\"" + Constants.S_201_ACCESS_TOKEN_RECEIVED + "\",\"status\":201}",
                response.content().utf8ToString());
    }

    // --- helpers -----------------------------------------------------------------

    /**
     * Runs the handler end to end.
     *
     * @param params query parameters
     * @param body request body, or null for a bodyless request
     * @param response what the transport layer answers, or null to answer nothing
     * @return the channel the response was written to
     */
    private FakeRestChannel dispatch(Map<String, String> params, String body, ActionResponse response)
            throws Exception {
        this.client.response = response;

        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withMethod(RestRequest.Method.POST)
                        .withPath(PluginSettings.SUBSCRIPTION_URI)
                        .withParams(new java.util.HashMap<>(params));
        if (body != null) {
            builder.withContent(new BytesArray(body), MediaTypeRegistry.JSON);
        }

        RestRequest request = builder.build();
        FakeRestChannel channel = new FakeRestChannel(request, true, 1);
        this.action.handleRequest(request, channel, this.client);
        return channel;
    }

    /** Captures the dispatched request and replies with a caller-supplied response. */
    private static class CapturingNodeClient extends NoOpNodeClient {
        private IndexSubscriptionRequest captured;
        private ActionResponse response;

        CapturingNodeClient(String testName) {
            super(testName);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
                ActionType<Response> action, Request request, ActionListener<Response> listener) {
            this.captured = (IndexSubscriptionRequest) request;
            if (this.response != null) {
                listener.onResponse((Response) this.response);
            }
        }
    }

    /**
     * Stand-in for {@code org.opensearch.security.action.simulate.PermissionCheckResponse}, which
     * lives in the security plugin's classloader and cannot be referenced from here. It reproduces
     * the two properties that matter: it is an {@link ActionResponse} but not a {@link
     * MessageStatusResponse}, and it is a {@link StatusToXContentObject}.
     */
    private static class PermissionCheckResponseDouble extends ActionResponse
            implements StatusToXContentObject {
        private final boolean accessAllowed;
        private final Set<String> missingPrivileges;

        PermissionCheckResponseDouble(boolean accessAllowed, Set<String> missingPrivileges) {
            this.accessAllowed = accessAllowed;
            this.missingPrivileges = missingPrivileges;
        }

        @Override
        public RestStatus status() {
            return RestStatus.OK;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder
                    .startObject()
                    .field("accessAllowed", this.accessAllowed)
                    .field("missingPrivileges", this.missingPrivileges)
                    .endObject();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeBoolean(this.accessAllowed);
            out.writeStringCollection(this.missingPrivileges);
        }
    }
}
