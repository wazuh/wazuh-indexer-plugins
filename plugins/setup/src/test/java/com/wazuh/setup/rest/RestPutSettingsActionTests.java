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

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.After;
import org.junit.Before;

import java.util.HashMap;

import com.wazuh.setup.settings.WazuhSettings;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
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

    @Mock private WazuhSettings wazuhSettings;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        this.action = new RestPutSettingsAction(this.wazuhSettings);
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
                        .withPath(WazuhSettings.SETTINGS_URI)
                        .withParams(new HashMap<>());
        if (body != null) {
            builder.withContent(new BytesArray(body), XContentType.JSON);
        }
        return builder.build();
    }

    /** Valid payload with index_raw_events=true -> 200. */
    public void testPut_validPayloadTrue_200() {
        RestRequest request = buildRequest("{\"engine\":{\"index_raw_events\":true}}");
        RestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        assertEquals(WazuhSettings.S_200_SETTINGS_UPDATED, response.getMessage());
        verify(this.wazuhSettings, times(1)).indexDocument(anyString());
    }

    /** Valid payload with index_raw_events=false -> 200. */
    public void testPut_validPayloadFalse_200() {
        RestRequest request = buildRequest("{\"engine\":{\"index_raw_events\":false}}");
        RestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.wazuhSettings, times(1)).indexDocument(anyString());
    }

    /** Request with no body -> 400. */
    public void testPut_noContent_400() {
        RestRequest request = buildRequest(null);
        RestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(WazuhSettings.E_400_INVALID_REQUEST_BODY, response.getMessage());
        verify(this.wazuhSettings, never()).indexDocument(anyString());
    }

    /** Malformed JSON body -> 400. */
    public void testPut_invalidJson_400() {
        RestRequest request = buildRequest("{not valid json");
        RestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(WazuhSettings.E_400_INVALID_REQUEST_BODY, response.getMessage());
        verify(this.wazuhSettings, never()).indexDocument(anyString());
    }

    /** Payload missing 'engine' object -> 400. */
    public void testPut_missingEngineField_400() {
        RestRequest request = buildRequest("{}");
        RestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(WazuhSettings.E_400_MISSING_SETTINGS, response.getMessage());
        verify(this.wazuhSettings, never()).indexDocument(anyString());
    }

    /** 'engine' present but missing 'index_raw_events' -> 400. */
    public void testPut_missingIndexRawEventsField_400() {
        RestRequest request = buildRequest("{\"engine\":{}}");
        RestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(WazuhSettings.E_400_MISSING_SETTINGS, response.getMessage());
        verify(this.wazuhSettings, never()).indexDocument(anyString());
    }

    /** 'index_raw_events' is a string, not a boolean -> 400. */
    public void testPut_nonBooleanValue_400() {
        RestRequest request = buildRequest("{\"engine\":{\"index_raw_events\":\"yes\"}}");
        RestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(WazuhSettings.E_400_MISSING_SETTINGS, response.getMessage());
        verify(this.wazuhSettings, never()).indexDocument(anyString());
    }

    /** Index operation throws an exception -> 500. */
    public void testPut_indexingFails_500() {
        doThrow(new RuntimeException("Index unavailable"))
                .when(this.wazuhSettings)
                .indexDocument(anyString());

        RestRequest request = buildRequest("{\"engine\":{\"index_raw_events\":true}}");
        RestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        assertEquals(WazuhSettings.E_500_INTERNAL_SERVER_ERROR, response.getMessage());
    }
}
