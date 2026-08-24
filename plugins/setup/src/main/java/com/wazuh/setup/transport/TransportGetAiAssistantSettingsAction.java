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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.util.Map;

import com.wazuh.setup.action.GetAiAssistantSettingsAction;
import com.wazuh.setup.action.GetAiAssistantSettingsRequest;
import com.wazuh.setup.action.GetAiAssistantSettingsResponse;
import com.wazuh.setup.index.AiAssistantSettingsAdminIndex;

/**
 * Transport action that reads either the AI assistant's settings/field policy, or its full provider
 * list. Gated by {@link GetAiAssistantSettingsAction#NAME} as a cluster permission; the underlying
 * read bypasses the system-index lockout on {@code .wazuh-internal-state} via {@link
 * AiAssistantSettingsAdminIndex}.
 */
public class TransportGetAiAssistantSettingsAction
        extends HandledTransportAction<GetAiAssistantSettingsRequest, GetAiAssistantSettingsResponse> {
    private static final Logger log =
            LogManager.getLogger(TransportGetAiAssistantSettingsAction.class);
    private static final String PROVIDERS_FIELD = "providers";

    private final AiAssistantSettingsAdminIndex settingsAdminIndex;

    @Inject
    public TransportGetAiAssistantSettingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            AiAssistantSettingsAdminIndex settingsAdminIndex) {
        super(
                GetAiAssistantSettingsAction.NAME,
                transportService,
                actionFilters,
                GetAiAssistantSettingsRequest::new);
        this.settingsAdminIndex = settingsAdminIndex;
    }

    @Override
    protected void doExecute(
            Task task,
            GetAiAssistantSettingsRequest request,
            ActionListener<GetAiAssistantSettingsResponse> listener) {
        ActionListener<Map<String, Object>> resultListener =
                ActionListener.wrap(
                        result -> listener.onResponse(new GetAiAssistantSettingsResponse(result)),
                        e -> {
                            log.error("Failed to read AI assistant settings: {}", e.getMessage(), e);
                            listener.onFailure(e);
                        });
        switch (request.getOperation()) {
            case SETTINGS:
                this.settingsAdminIndex.getSettings(resultListener);
                break;
            case LIST_PROVIDERS:
                this.settingsAdminIndex.listProviders(
                        ActionListener.wrap(
                                providers -> resultListener.onResponse(Map.of(PROVIDERS_FIELD, providers)),
                                resultListener::onFailure));
                break;
        }
    }
}
