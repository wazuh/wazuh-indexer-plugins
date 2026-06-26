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
package com.wazuh.setup.transport;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.junit.After;
import org.junit.Before;

import com.wazuh.setup.action.PutSettingsRequest;
import com.wazuh.setup.action.PutSettingsResponse;
import com.wazuh.setup.index.SettingsIndex;
import com.wazuh.setup.model.WazuhSettings;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link TransportPutSettingsAction}, which validates and persists the settings
 * document gated behind the {@code plugin:setup/settings/write} permission and the {@code
 * plugins.setup.settings_update.enabled} setting.
 */
public class TransportPutSettingsActionTests extends OpenSearchTestCase {

    private TransportPutSettingsAction action;
    private AutoCloseable mocks;

    @Mock private SettingsIndex settingsIndex;
    @Mock private IndexResponse indexResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        this.action = newAction(Settings.EMPTY);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.mocks != null) {
            this.mocks.close();
        }
    }

    private TransportPutSettingsAction newAction(Settings settings) {
        return new TransportPutSettingsAction(
                mock(TransportService.class), mock(ActionFilters.class), this.settingsIndex, settings);
    }

    @SuppressWarnings("unchecked")
    private void mockIndexSuccess() {
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(1);
                            listener.onResponse(this.indexResponse);
                            return null;
                        })
                .when(this.settingsIndex)
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    private void mockIndexFailure(Exception exception) {
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(1);
                            listener.onFailure(exception);
                            return null;
                        })
                .when(this.settingsIndex)
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    private PutSettingsResponse execute(String payload) {
        PlainActionFuture<PutSettingsResponse> future = PlainActionFuture.newFuture();
        this.action.doExecute(mock(Task.class), new PutSettingsRequest(payload), future);
        return future.actionGet();
    }

    @SuppressWarnings("unchecked")
    public void testSettingsUpdateDisabled_Forbidden() {
        this.action =
                newAction(Settings.builder().put("plugins.setup.settings_update.enabled", false).build());

        PutSettingsResponse response = this.execute("{\"engine\":{\"index_raw_events\":true}}");

        assertEquals(RestStatus.FORBIDDEN, response.getStatus());
        assertEquals(SettingsIndex.E_403_SETTINGS_UPDATE_DISABLED, response.getMessage());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    public void testValidPayloadTrue_200() {
        mockIndexSuccess();

        PutSettingsResponse response = this.execute("{\"engine\":{\"index_raw_events\":true}}");

        assertEquals(RestStatus.OK, response.getStatus());
        verify(this.settingsIndex, times(1))
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    public void testNoContent_400() {
        PutSettingsResponse response = this.execute(null);

        assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    public void testInvalidJson_400() {
        PutSettingsResponse response = this.execute("{not valid json");

        assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    public void testMissingEngineField_400() {
        PutSettingsResponse response = this.execute("{}");

        assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    @SuppressWarnings("unchecked")
    public void testNonBooleanValue_400() {
        PutSettingsResponse response = this.execute("{\"engine\":{\"index_raw_events\":\"yes\"}}");

        assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        verify(this.settingsIndex, never())
                .indexDocument(any(WazuhSettings.class), any(ActionListener.class));
    }

    public void testIndexingFails_500() {
        mockIndexFailure(new RuntimeException("Index unavailable"));

        PutSettingsResponse response = this.execute("{\"engine\":{\"index_raw_events\":true}}");

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.getStatus());
    }
}
