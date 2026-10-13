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

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.client.NoOpNodeClient;
import org.opensearch.test.rest.FakeRestChannel;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.Assert;
import org.junit.Before;

import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.action.VersionCheckResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

public class RestGetVersionCheckActionTests extends OpenSearchTestCase {
    private RestGetVersionCheckAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.action = new RestGetVersionCheckAction();
    }

    public void testRouteMethod() {
        Assert.assertEquals(1, this.action.routes().size());
        Assert.assertEquals(RestRequest.Method.GET, this.action.routes().get(0).getMethod());
    }

    public void testRoutePath() {
        Assert.assertEquals(PluginSettings.VERSION_CHECK_URI, this.action.routes().get(0).getPath());
    }

    public void testName() {
        Assert.assertEquals("content_manager_version_check_get", this.action.getName());
    }

    /** A rate-limited answer is a 429 carrying a Retry-After header. */
    public void testRateLimitedResponseHasRetryAfterHeader() throws Exception {
        RestResponse response =
                this.dispatch(
                        new VersionCheckResponse("Too many version checks.", RestStatus.TOO_MANY_REQUESTS, 7));

        Assert.assertEquals(RestStatus.TOO_MANY_REQUESTS, response.status());
        Assert.assertEquals(List.of("7"), response.getHeaders().get("Retry-After"));
    }

    /** Any other answer carries no Retry-After header. */
    public void testSuccessResponseHasNoRetryAfterHeader() throws Exception {
        RestResponse response = this.dispatch(new VersionCheckResponse("{}", RestStatus.OK, Map.of()));

        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertNull(response.getHeaders().get("Retry-After"));
    }

    /** Runs the handler end to end with the transport layer answering {@code transportResponse}. */
    private RestResponse dispatch(VersionCheckResponse transportResponse) throws Exception {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withMethod(RestRequest.Method.GET)
                        .withPath(PluginSettings.VERSION_CHECK_URI)
                        .build();
        FakeRestChannel channel = new FakeRestChannel(request, true, 1);
        try (RespondingNodeClient client = new RespondingNodeClient(getTestName(), transportResponse)) {
            this.action.handleRequest(request, channel, client);
        }
        return channel.capturedResponse();
    }

    /** Replies to every action with a fixed response. */
    private static class RespondingNodeClient extends NoOpNodeClient {
        private final ActionResponse response;

        RespondingNodeClient(String testName, ActionResponse response) {
            super(testName);
            this.response = response;
        }

        @Override
        @SuppressWarnings("unchecked")
        public <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
                ActionType<Response> action, Request request, ActionListener<Response> listener) {
            listener.onResponse((Response) this.response);
        }
    }
}
