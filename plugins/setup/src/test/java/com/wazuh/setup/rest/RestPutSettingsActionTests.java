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
package com.wazuh.setup.rest;

import org.opensearch.common.CheckedConsumer;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.util.HashMap;

import com.wazuh.setup.action.PutSettingsAction;
import com.wazuh.setup.action.PutSettingsRequest;
import com.wazuh.setup.action.PutSettingsResponse;
import com.wazuh.setup.index.SettingsIndex;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link RestPutSettingsAction}. The handler delegates to {@link PutSettingsAction};
 * the validation/persistence logic is covered by {@code TransportPutSettingsActionTests}.
 */
public class RestPutSettingsActionTests extends OpenSearchTestCase {

    private final RestPutSettingsAction action = new RestPutSettingsAction();

    public void testGetNameAndRoutes() {
        assertEquals("wazuh_settings", this.action.getName());
        assertEquals(1, this.action.routes().size());
        assertEquals(RestRequest.Method.PUT, this.action.routes().get(0).getMethod());
    }

    /** The handler maps the transport response status onto the REST channel response. */
    public void testDelegatesAndMapsStatus() throws Exception {
        NodeClient client = mock(NodeClient.class, Answers.RETURNS_DEEP_STUBS);
        doAnswer(
                        invocation -> {
                            ActionListener<PutSettingsResponse> listener = invocation.getArgument(2);
                            listener.onResponse(
                                    new PutSettingsResponse(SettingsIndex.S_200_SETTINGS_UPDATED, RestStatus.OK));
                            return null;
                        })
                .when(client)
                .execute(eq(PutSettingsAction.INSTANCE), any(PutSettingsRequest.class), any());

        RestRequest request =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(SettingsIndex.SETTINGS_URI)
                        .withParams(new HashMap<>())
                        .withContent(
                                new BytesArray("{\"engine\":{\"index_raw_events\":true}}"), XContentType.JSON)
                        .build();
        RestChannel channel = mock(RestChannel.class, Answers.RETURNS_DEEP_STUBS);

        CheckedConsumer<RestChannel, Exception> consumer = this.action.prepareRequest(request, client);
        consumer.accept(channel);

        ArgumentCaptor<BytesRestResponse> captor = ArgumentCaptor.forClass(BytesRestResponse.class);
        verify(channel).sendResponse(captor.capture());
        assertEquals(RestStatus.OK, captor.getValue().status());
    }
}
