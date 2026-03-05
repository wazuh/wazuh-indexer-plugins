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
package com.wazuh.setup.settings;

import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import com.wazuh.setup.index.SettingsIndex;
import com.wazuh.setup.model.WazuhSettings;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SettingsIndex}. Validates indexDefaultValues behavior: writes default
 * settings when no document exists, skips when already initialized, and swallows exceptions.
 */
public class SettingsIndexTests extends OpenSearchTestCase {

    private SettingsIndex settingsIndex;
    private AutoCloseable mocks;

    @Mock private Client client;
    @Mock private GetRequestBuilder getRequestBuilder;
    @Mock private GetResponse getResponse;
    @Mock private ActionFuture<IndexResponse> indexFuture;
    @Mock private IndexResponse indexResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);

        this.settingsIndex = new SettingsIndex(SettingsIndex.INDEX_NAME, "templates/settings");
        this.settingsIndex.setClient(this.client);

        when(this.client.prepareGet(SettingsIndex.INDEX_NAME, SettingsIndex.SETTINGS_ID))
                .thenReturn(this.getRequestBuilder);
        when(this.getRequestBuilder.get()).thenReturn(this.getResponse);
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
    public void testIndexDefaultValues_noDocument_writesDefaultFalse() {
        when(this.getResponse.isExists()).thenReturn(false);
        when(this.client.index(any(IndexRequest.class))).thenReturn(this.indexFuture);

        this.settingsIndex.indexDefaultValues();

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest captured = captor.getValue();
        assertEquals(SettingsIndex.INDEX_NAME, captured.index());
        assertEquals(SettingsIndex.SETTINGS_ID, captured.id());
        assertTrue(
                "Payload must contain engine.index_raw_events=false",
                captured.source().utf8ToString().contains("\"index_raw_events\":false"));
    }

    /** Document already exists -> indexDefaultValues() is a no-op; index() is never called. */
    public void testIndexDefaultValues_documentExists_isNoOp() {
        when(this.getResponse.isExists()).thenReturn(true);

        this.settingsIndex.indexDefaultValues();

        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** prepareGet throws -> exception is swallowed; index() is never called. */
    public void testIndexDefaultValues_exception_swallowed() {
        when(this.getRequestBuilder.get()).thenThrow(new RuntimeException("Index unavailable"));

        this.settingsIndex.indexDefaultValues();

        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /** indexDocument calls the async index method with correct request and listener. */
    @SuppressWarnings("unchecked")
    public void testIndexDocument_callsAsyncIndex() {
        WazuhSettings settings = WazuhSettings.createDefault();
        ActionListener<IndexResponse> listener =
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse response) {
                        // Success callback
                    }

                    @Override
                    public void onFailure(Exception e) {
                        fail("Should not fail");
                    }
                };

        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> callbackListener = invocation.getArgument(1);
                            callbackListener.onResponse(indexResponse);
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any(ActionListener.class));

        this.settingsIndex.indexDocument(settings, listener);

        ArgumentCaptor<IndexRequest> requestCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(requestCaptor.capture(), any(ActionListener.class));

        IndexRequest captured = requestCaptor.getValue();
        assertEquals(SettingsIndex.INDEX_NAME, captured.index());
        assertEquals(SettingsIndex.SETTINGS_ID, captured.id());
        assertTrue(
                "Payload must contain engine.index_raw_events",
                captured.source().utf8ToString().contains("index_raw_events"));
    }
}
