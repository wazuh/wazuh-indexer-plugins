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
package com.wazuh.contentmanager.engine.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EngineSettings}. Validates initialization behavior: writes default settings
 * when no document exists, skips when already initialized, and swallows exceptions.
 */
public class EngineSettingsTests extends OpenSearchTestCase {

    private EngineSettings engineSettings;
    private AutoCloseable mocks;

    @Mock private ContentIndex settingsIndex;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.builder().build());
        this.engineSettings = new EngineSettings(this.settingsIndex);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.mocks != null) {
            this.mocks.close();
        }
    }

    /** No existing document -> default settings with index_raw_events=false are persisted. */
    public void testInitialize_noDocument_writesDefaultFalse() throws Exception {
        when(this.settingsIndex.getDocument(PluginSettings.ENGINE_SETTINGS_ID)).thenReturn(null);

        this.engineSettings.initialize();

        ObjectMapper mapper = new ObjectMapper();
        JsonNode expected =
                mapper
                        .createObjectNode()
                        .set(
                                Constants.KEY_ENGINE,
                                mapper.createObjectNode().put(Constants.KEY_INDEX_RAW_EVENTS, false));

        verify(this.settingsIndex, times(1))
                .indexDocument(eq(PluginSettings.ENGINE_SETTINGS_ID), eq(expected));
    }

    /** Document already exists -> initialize() is a no-op; indexDocument is never called. */
    public void testInitialize_documentExists_isNoOp() throws Exception {
        JsonNode existing = new ObjectMapper().readTree("{\"engine\":{\"index_raw_events\":true}}");
        when(this.settingsIndex.getDocument(PluginSettings.ENGINE_SETTINGS_ID)).thenReturn(existing);

        this.engineSettings.initialize();

        verify(this.settingsIndex, never()).indexDocument(any(), any(JsonNode.class));
    }

    /** getDocument throws -> exception is swallowed; indexDocument is never called. */
    public void testInitialize_getDocumentThrows_noExceptionPropagated() throws Exception {
        when(this.settingsIndex.getDocument(PluginSettings.ENGINE_SETTINGS_ID))
                .thenThrow(new RuntimeException("Index unavailable"));

        // Must not throw
        this.engineSettings.initialize();

        verify(this.settingsIndex, never()).indexDocument(any(), any(JsonNode.class));
    }
}
