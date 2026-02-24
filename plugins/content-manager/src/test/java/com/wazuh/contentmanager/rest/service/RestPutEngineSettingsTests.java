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

import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RestPutEngineSettings}. Validates PUT engine settings request handling,
 * payload validation, and index operation responses.
 */
public class RestPutEngineSettingsTests extends OpenSearchTestCase {

    private RestPutEngineSettings action;
    private AutoCloseable mocks;

    @Mock private ContentIndex settingsIndex;
    @Mock private IndexResponse indexResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        Settings settings = Settings.builder().build();
        PluginSettings.getInstance(settings);
        this.action = new RestPutEngineSettings(this.settingsIndex);
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
        Map<String, String> params = new HashMap<>();
        FakeRestRequest.Builder builder =
                new FakeRestRequest.Builder(this.xContentRegistry())
                        .withMethod(RestRequest.Method.PUT)
                        .withPath(PluginSettings.ENGINE_SETTINGS_URI)
                        .withParams(params);
        if (body != null) {
            builder.withContent(new BytesArray(body), XContentType.JSON);
        }
        return builder.build();
    }

    /**
     * Valid payload with index_raw_events=true -> 200.
     *
     * @throws Exception On indexing failure
     */
    public void testPut_validPayloadTrue_200() throws Exception {
        when(this.settingsIndex.indexDocument(anyString(), any(JsonNode.class)))
                .thenReturn(this.indexResponse);

        RestRequest request = this.buildRequest("{\"engine\":{\"index_raw_events\":true}}");
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.S_200_SETTINGS_UPDATED, response.getMessage());
        verify(this.settingsIndex, times(1)).indexDocument(anyString(), any(JsonNode.class));
    }

    /**
     * Valid payload with index_raw_events=false -> 200.
     *
     * @throws Exception On indexing failure
     */
    public void testPut_validPayloadFalse_200() throws Exception {
        when(this.settingsIndex.indexDocument(anyString(), any(JsonNode.class)))
                .thenReturn(this.indexResponse);

        RestRequest request = this.buildRequest("{\"engine\":{\"index_raw_events\":false}}");
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        verify(this.settingsIndex, times(1)).indexDocument(anyString(), any(JsonNode.class));
    }

    /**
     * Request with no body -> 400.
     *
     * @throws Exception On unexpected failure
     */
    public void testPut_noContent_400() throws Exception {
        RestRequest request = this.buildRequest(null);
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
        verify(this.settingsIndex, never()).indexDocument(anyString(), any(JsonNode.class));
    }

    /**
     * Malformed JSON body -> 400.
     *
     * @throws Exception On unexpected failure
     */
    public void testPut_invalidJson_400() throws Exception {
        RestRequest request = this.buildRequest("{not valid json");
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_INVALID_REQUEST_BODY, response.getMessage());
        verify(this.settingsIndex, never()).indexDocument(anyString(), any(JsonNode.class));
    }

    /**
     * Payload missing 'engine' object -> 400.
     *
     * @throws Exception On unexpected failure
     */
    public void testPut_missingEngineField_400() throws Exception {
        RestRequest request = this.buildRequest("{}");
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_MISSING_ENGINE_SETTINGS, response.getMessage());
        verify(this.settingsIndex, never()).indexDocument(anyString(), any(JsonNode.class));
    }

    /**
     * 'engine' present but missing 'index_raw_events' -> 400.
     *
     * @throws Exception On unexpected failure
     */
    public void testPut_missingIndexRawEventsField_400() throws Exception {
        RestRequest request = this.buildRequest("{\"engine\":{}}");
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_MISSING_ENGINE_SETTINGS, response.getMessage());
        verify(this.settingsIndex, never()).indexDocument(anyString(), any(JsonNode.class));
    }

    /**
     * 'index_raw_events' is a string, not a boolean -> 400.
     *
     * @throws Exception On unexpected failure
     */
    public void testPut_nonBooleanValue_400() throws Exception {
        RestRequest request = this.buildRequest("{\"engine\":{\"index_raw_events\":\"yes\"}}");
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_400_MISSING_ENGINE_SETTINGS, response.getMessage());
        verify(this.settingsIndex, never()).indexDocument(anyString(), any(JsonNode.class));
    }

    /**
     * Index operation throws an exception -> 500.
     *
     * @throws Exception On indexing failure
     */
    public void testPut_indexingFails_500() throws Exception {
        when(this.settingsIndex.indexDocument(anyString(), any(JsonNode.class)))
                .thenThrow(new IOException("Index unavailable"));

        RestRequest request = this.buildRequest("{\"engine\":{\"index_raw_events\":true}}");
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.E_500_INTERNAL_SERVER_ERROR, response.getMessage());
    }
}
