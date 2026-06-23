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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import com.wazuh.setup.action.PutSettingsAction;
import com.wazuh.setup.action.PutSettingsRequest;
import com.wazuh.setup.action.PutSettingsResponse;
import com.wazuh.setup.index.SettingsIndex;
import com.wazuh.setup.model.WazuhSettings;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Transport action that persists Wazuh settings to the {@code .wazuh-settings} index. The write is
 * gated here so the security plugin enforces {@link PutSettingsAction#NAME} as a cluster permission
 * and so the {@code plugins.setup.sensitive_config.locked} setting can block modification entirely.
 */
public class TransportPutSettingsAction
        extends HandledTransportAction<PutSettingsRequest, PutSettingsResponse> {
    private static final Logger log = LogManager.getLogger(TransportPutSettingsAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final SettingsIndex settingsIndex;
    private final Settings settings;

    @Inject
    public TransportPutSettingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SettingsIndex settingsIndex,
            Settings settings) {
        super(PutSettingsAction.NAME, transportService, actionFilters, PutSettingsRequest::new);
        this.settingsIndex = settingsIndex;
        this.settings = settings;
    }

    @Override
    protected void doExecute(
            Task task, PutSettingsRequest request, ActionListener<PutSettingsResponse> listener) {
        // Lockdown gate: when enabled, sensitive configuration cannot be modified by anyone.
        if (PluginSettings.isSensitiveConfigLocked(this.settings)) {
            listener.onResponse(
                    new PutSettingsResponse(
                            SettingsIndex.E_403_SENSITIVE_CONFIG_LOCKED, RestStatus.FORBIDDEN));
            return;
        }

        String payload = request.getPayload();

        // 1. Validate content presence
        if (payload == null || payload.isBlank()) {
            listener.onResponse(
                    new PutSettingsResponse(
                            SettingsIndex.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
            return;
        }

        // 2. Parse JSON
        JsonNode root;
        try {
            root = MAPPER.readTree(payload);
        } catch (Exception e) {
            listener.onResponse(
                    new PutSettingsResponse(
                            SettingsIndex.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
            return;
        }

        // 3. Validate structure using model method
        String validationError = WazuhSettings.validate(root);
        if (validationError != null) {
            listener.onResponse(new PutSettingsResponse(validationError, RestStatus.BAD_REQUEST));
            return;
        }

        // 4. Parse into model and persist asynchronously
        WazuhSettings wazuhSettings = WazuhSettings.fromPayload(root);
        this.settingsIndex.indexDocument(
                wazuhSettings,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        log.info("Wazuh settings updated: {}", wazuhSettings);
                        listener.onResponse(
                                new PutSettingsResponse(SettingsIndex.S_200_SETTINGS_UPDATED, RestStatus.OK));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        OpenSearchSecurityException secEx = extractSecurityException(e);
                        if (secEx != null) {
                            listener.onResponse(new PutSettingsResponse(secEx.getMessage(), secEx.status()));
                            return;
                        }
                        log.error("Failed to persist settings: {}", e.getMessage(), e);
                        listener.onResponse(
                                new PutSettingsResponse(
                                        SettingsIndex.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
                    }
                });
    }

    /**
     * Walks the exception cause chain looking for an {@link OpenSearchSecurityException}. Returns it
     * if found, or {@code null} otherwise.
     *
     * @param throwable the throwable to inspect.
     * @return the security exception, or null.
     */
    private static OpenSearchSecurityException extractSecurityException(Throwable throwable) {
        Throwable cause = throwable;
        while (cause != null) {
            if (cause instanceof OpenSearchSecurityException) {
                return (OpenSearchSecurityException) cause;
            }
            cause = cause.getCause();
        }
        return null;
    }
}
