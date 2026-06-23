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

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.common.CheckedConsumer;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;
import org.junit.After;
import org.junit.Before;

import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.action.PutPolicyAction;
import com.wazuh.contentmanager.action.PutPolicyRequest;
import com.wazuh.contentmanager.action.PutPolicyResponse;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RestPutPolicyAction}. The handler delegates the policy write to {@link
 * PutPolicyAction} and reloads the Engine when the transport action signals a standard-space hash
 * change. The validation/write logic itself is covered by {@code TransportPutPolicyActionTests}.
 */
public class RestPutPolicyActionTests extends OpenSearchTestCase {
    private SpaceService spaceService;
    private EngineService engineService;
    private NodeClient client;
    private RestPutPolicyAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(Settings.EMPTY);
        this.spaceService = mock(SpaceService.class);
        this.engineService = mock(EngineService.class);
        this.client = mock(NodeClient.class, Answers.RETURNS_DEEP_STUBS);
        this.action = new RestPutPolicyAction(this.spaceService, this.engineService);
        when(this.spaceService.buildEnginePayload(anyString())).thenReturn(mock(JsonNode.class));
        when(this.engineService.promote(any()))
                .thenReturn(new RestResponse("OK", RestStatus.OK.getStatus()));
    }

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettings.resetForTesting();
        super.tearDown();
    }

    public void testGetNameAndRoutes() {
        assertEquals("content_manager_policy_update", this.action.getName());
        assertEquals(1, this.action.routes().size());
        assertEquals(RestRequest.Method.PUT, this.action.routes().get(0).getMethod());
    }

    /**
     * When the transport action signals a reload, the handler loads the standard space into the
     * Engine.
     */
    public void testReloadEngine_WhenSignalled() throws Exception {
        stubExecuteToRespond(new PutPolicyResponse("policy-id", RestStatus.OK, true));

        this.invoke();

        verify(this.engineService, times(1)).promote(any());
    }

    /** When the transport action does not signal a reload, the Engine is left untouched. */
    public void testReloadEngine_Skipped_WhenNotSignalled() throws Exception {
        stubExecuteToRespond(new PutPolicyResponse("policy-id", RestStatus.OK, false));

        this.invoke();

        verify(this.engineService, never()).promote(any());
    }

    private void stubExecuteToRespond(PutPolicyResponse response) {
        doAnswer(
                        invocation -> {
                            ActionListener<PutPolicyResponse> listener = invocation.getArgument(2);
                            listener.onResponse(response);
                            return null;
                        })
                .when(this.client)
                .execute(eq(PutPolicyAction.INSTANCE), any(PutPolicyRequest.class), any());
    }

    private void invoke() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("space", "standard");
        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.POLICY_URI)
                        .withParams(params)
                        .withContent(new BytesArray("{\"resource\": {}}"), XContentType.JSON)
                        .build();
        CheckedConsumer<RestChannel, Exception> consumer =
                this.action.prepareRequest(request, this.client);
        consumer.accept(mock(RestChannel.class, Answers.RETURNS_DEEP_STUBS));
    }
}
