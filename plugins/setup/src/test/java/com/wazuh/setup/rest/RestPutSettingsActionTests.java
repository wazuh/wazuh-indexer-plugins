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

import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.After;
import org.junit.Before;

import java.util.HashMap;

import com.wazuh.setup.index.SettingsIndex;
import com.wazuh.setup.model.WazuhSettings;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link RestPutSettingsAction}. Validates PUT settings request handling, payload
 * validation, and index operation responses.
 */
public class RestPutSettingsActionTests extends OpenSearchTestCase {

    private RestPutSettingsAction action;
    private AutoCloseable mocks;

    @Mock private SettingsIndex settingsIndex;
    @Mock private RestChannel channel;
    @Mock private IndexResponse indexResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        this.action = new RestPutSettingsAction(this.settingsIndex);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.mocks != null) {
            this.mocks.close();
        }
    }

    /** Helper to build a PUT request with the given body. */
    private RestRequest buildRequest(String body) {
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(SettingsIndex.SETTINGS_URI)
                        .withParams(new HashMap<>());
        if (body != null) {
            builder.withContent(new BytesArray(body), XContentType.JSON);
        }
        return builder.build();
    }

    /** Configures the mock to invoke onResponse callback. */
    @SuppressWarnings("unchecked")
    private void mockIndexDocumentSuccess() {
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(1);
                            listener.onResponse(this.indexResponse);
                            return null;
                        })
                .when(this.settingsIndex)
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** Configures the mock to invoke onFailure callback. */
    @SuppressWarnings("unchecked")
    private void mockIndexDocumentFailure(Exception exception) {
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(1);
                            listener.onFailure(exception);
                            return null;
                        })
                .when(this.settingsIndex)
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** Captures and returns the BytesRestResponse sent to the channel. */
    private BytesRestResponse captureResponse() {
        ArgumentCaptor<BytesRestResponse> captor = ArgumentCaptor.forClass(BytesRestResponse.class);
        verify(this.channel).sendResponse(captor.capture());
        return captor.getValue();
    }

    /** Valid payload with index_raw_events=true -> 200. */
    @SuppressWarnings("unchecked")
    public void testPut_validPayloadTrue_200() {
        mockIndexDocumentSuccess();
        RestRequest request = buildRequest("{\"engine\":{\"index_raw_events\":true}}");

        this.action.handleRequest(request, this.channel);

        BytesRestResponse response = captureResponse();
        assertEquals(RestStatus.OK, response.status());
        verify(this.settingsIndex, times(1))
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** Valid payload with index_raw_events=false -> 200. */
    @SuppressWarnings("unchecked")
    public void testPut_validPayloadFalse_200() {
        mockIndexDocumentSuccess();
        RestRequest request = buildRequest("{\"engine\":{\"index_raw_events\":false}}");

        this.action.handleRequest(request, this.channel);

        BytesRestResponse response = captureResponse();
        assertEquals(RestStatus.OK, response.status());
        verify(this.settingsIndex, times(1))
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** Request with no body -> 400. */
    @SuppressWarnings("unchecked")
    public void testPut_noContent_400() {
        RestRequest request = buildRequest(null);

        this.action.handleRequest(request, this.channel);

        BytesRestResponse response = captureResponse();
        assertEquals(RestStatus.BAD_REQUEST, response.status());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** Malformed JSON body -> 400. */
    @SuppressWarnings("unchecked")
    public void testPut_invalidJson_400() {
        RestRequest request = buildRequest("{not valid json");

        this.action.handleRequest(request, this.channel);

        BytesRestResponse response = captureResponse();
        assertEquals(RestStatus.BAD_REQUEST, response.status());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** Payload missing 'engine' object -> 400. */
    @SuppressWarnings("unchecked")
    public void testPut_missingEngineField_400() {
        RestRequest request = buildRequest("{}");

        this.action.handleRequest(request, this.channel);

        BytesRestResponse response = captureResponse();
        assertEquals(RestStatus.BAD_REQUEST, response.status());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** 'engine' present but missing 'index_raw_events' -> 400. */
    @SuppressWarnings("unchecked")
    public void testPut_missingIndexRawEventsField_400() {
        RestRequest request = buildRequest("{\"engine\":{}}");

        this.action.handleRequest(request, this.channel);

        BytesRestResponse response = captureResponse();
        assertEquals(RestStatus.BAD_REQUEST, response.status());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** 'index_raw_events' is a string, not a boolean -> 400 (type validation fails). */
    @SuppressWarnings("unchecked")
    public void testPut_nonBooleanValue_400() {
        RestRequest request = buildRequest("{\"engine\":{\"index_raw_events\":\"yes\"}}");

        this.action.handleRequest(request, this.channel);

        BytesRestResponse response = captureResponse();
        assertEquals(RestStatus.BAD_REQUEST, response.status());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    /** Index operation throws an exception -> 500. */
    @SuppressWarnings("unchecked")
    public void testPut_indexingFails_500() {
        mockIndexDocumentFailure(new RuntimeException("Index unavailable"));
        RestRequest request = buildRequest("{\"engine\":{\"index_raw_events\":true}}");

        this.action.handleRequest(request, this.channel);

        BytesRestResponse response = captureResponse();
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
    }
}
