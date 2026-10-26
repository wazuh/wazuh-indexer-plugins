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
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.client.NoOpNodeClient;
import org.opensearch.test.rest.FakeRestChannel;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.Assert;
import org.junit.Before;

import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.action.TriggerUpdateRequest;
import com.wazuh.contentmanager.settings.PluginSettings;

public class RestPostUpdateActionTests extends OpenSearchTestCase {
    private RestPostUpdateAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.action = new RestPostUpdateAction();
    }

    public void testRouteMethod() {
        Assert.assertEquals(1, this.action.routes().size());
        Assert.assertEquals(RestRequest.Method.POST, this.action.routes().get(0).getMethod());
    }

    public void testRoutePath() {
        Assert.assertEquals(PluginSettings.UPDATE_URI, this.action.routes().get(0).getPath());
    }

    public void testName() {
        Assert.assertEquals("content_manager_subscription_update", this.action.getName());
    }

    /** {@code ?offline=true} requests an offline update. */
    public void testOfflineParameter() throws Exception {
        Assert.assertTrue(this.dispatch(Map.of("offline", "true")).isOffline());
    }

    /** Without the parameter, or with it false, the update is a regular one. */
    public void testOnlineByDefault() throws Exception {
        Assert.assertFalse(this.dispatch(Map.of()).isOffline());
        Assert.assertFalse(this.dispatch(Map.of("offline", "false")).isOffline());
    }

    /** A value that is not a boolean is rejected before any update starts. */
    public void testInvalidOfflineValue() {
        expectThrows(IllegalArgumentException.class, () -> this.dispatch(Map.of("offline", "maybe")));
    }

    /**
     * Sends {@code POST /update} with the given query parameters through the handler, and returns the
     * request it hands to the transport layer.
     */
    private TriggerUpdateRequest dispatch(Map<String, String> params) throws Exception {
        try (CapturingNodeClient client = new CapturingNodeClient(getTestName())) {
            RestRequest request =
                    new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                            .withMethod(RestRequest.Method.POST)
                            .withPath(PluginSettings.UPDATE_URI)
                            .withParams(new HashMap<>(params))
                            .build();
            this.action.handleRequest(request, new FakeRestChannel(request, true, 1), client);
            return client.captured;
        }
    }

    /** Captures the dispatched request without answering it. */
    private static class CapturingNodeClient extends NoOpNodeClient {
        private TriggerUpdateRequest captured;

        CapturingNodeClient(String testName) {
            super(testName);
        }

        @Override
        public <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
                ActionType<Response> action, Request request, ActionListener<Response> listener) {
            this.captured = (TriggerUpdateRequest) request;
        }
    }
}
