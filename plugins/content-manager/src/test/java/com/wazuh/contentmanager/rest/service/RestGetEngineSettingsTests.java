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
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RestGetEngineSettings}. Validates GET engine settings responses including
 * stored values, defaults when no document exists, and error handling.
 */
public class RestGetEngineSettingsTests extends OpenSearchTestCase {

    private RestGetEngineSettings action;
    private AutoCloseable mocks;
    private static final ObjectMapper mapper = new ObjectMapper();

    @Mock private ContentIndex settingsIndex;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        Settings settings = Settings.builder().build();
        PluginSettings.getInstance(settings);
        this.action = new RestGetEngineSettings(this.settingsIndex);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.mocks != null) {
            this.mocks.close();
        }
    }

    /** Document exists with index_raw_events=true → 200 with stored value. */
    public void testGet_documentExists_returnsStoredValue_200() throws Exception {
        JsonNode stored = mapper.readTree("{\"engine\":{\"index_raw_events\":true}}");
        when(this.settingsIndex.getDocument(anyString())).thenReturn(stored);

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.OK, response.status());
        JsonNode body = mapper.readTree(response.content().toBytesRef().bytes);
        Assert.assertTrue(
                body.path(Constants.KEY_ENGINE).path(Constants.KEY_INDEX_RAW_EVENTS).asBoolean());
    }

    /** Document exists with index_raw_events=false → 200 with stored value. */
    public void testGet_documentExistsFalse_returnsStoredValue_200() throws Exception {
        JsonNode stored = mapper.readTree("{\"engine\":{\"index_raw_events\":false}}");
        when(this.settingsIndex.getDocument(anyString())).thenReturn(stored);

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.OK, response.status());
        JsonNode body = mapper.readTree(response.content().toBytesRef().bytes);
        Assert.assertFalse(
                body.path(Constants.KEY_ENGINE).path(Constants.KEY_INDEX_RAW_EVENTS).asBoolean());
    }

    /** No document exists (getDocument returns null) → 200 with default false. */
    public void testGet_documentNotFound_returnsDefault_200() throws Exception {
        when(this.settingsIndex.getDocument(anyString())).thenReturn(null);

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.OK, response.status());
        JsonNode body = mapper.readTree(response.content().toBytesRef().bytes);
        Assert.assertFalse(
                body.path(Constants.KEY_ENGINE).path(Constants.KEY_INDEX_RAW_EVENTS).asBoolean());
    }

    /** getDocument throws an exception → 500. */
    public void testGet_indexError_500() throws Exception {
        when(this.settingsIndex.getDocument(anyString()))
                .thenThrow(new RuntimeException("Index unavailable"));

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
        JsonNode body = mapper.readTree(response.content().toBytesRef().bytes);
        Assert.assertEquals(Constants.E_500_INTERNAL_SERVER_ERROR, body.path("message").asText());
    }
}
