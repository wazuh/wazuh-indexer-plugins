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
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.util.Map;
import java.util.UUID;

import com.wazuh.setup.action.PutAiAssistantSettingsAction;
import com.wazuh.setup.action.PutAiAssistantSettingsRequest;
import com.wazuh.setup.action.PutAiAssistantSettingsResponse;
import com.wazuh.setup.index.AiAssistantSettingsAdminIndex;

/**
 * Transport action that writes the AI assistant's settings, field policy and providers. Gated by
 * {@link PutAiAssistantSettingsAction#NAME} as a cluster permission; the underlying write bypasses
 * the system-index lockout on {@code .wazuh-internal-state} via {@link
 * AiAssistantSettingsAdminIndex}.
 */
public class TransportPutAiAssistantSettingsAction
        extends HandledTransportAction<PutAiAssistantSettingsRequest, PutAiAssistantSettingsResponse> {
    private static final Logger log =
            LogManager.getLogger(TransportPutAiAssistantSettingsAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ID_FIELD = "id";

    private final AiAssistantSettingsAdminIndex settingsAdminIndex;

    @Inject
    public TransportPutAiAssistantSettingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            AiAssistantSettingsAdminIndex settingsAdminIndex) {
        super(
                PutAiAssistantSettingsAction.NAME,
                transportService,
                actionFilters,
                PutAiAssistantSettingsRequest::new);
        this.settingsAdminIndex = settingsAdminIndex;
    }

    @Override
    protected void doExecute(
            Task task,
            PutAiAssistantSettingsRequest request,
            ActionListener<PutAiAssistantSettingsResponse> listener) {
        switch (request.getOperation()) {
            case SETTINGS:
                this.putSettings(request, listener);
                break;
            case PUT_PROVIDER:
                this.putProvider(request, listener);
                break;
            case DELETE_PROVIDER:
                this.deleteProvider(request, listener);
                break;
        }
    }

    private void putSettings(
            PutAiAssistantSettingsRequest request,
            ActionListener<PutAiAssistantSettingsResponse> listener) {
        Map<String, Object> body;
        try {
            body = parseBody(request.getPayload());
        } catch (Exception e) {
            listener.onResponse(
                    new PutAiAssistantSettingsResponse(
                            "Invalid request body.", RestStatus.BAD_REQUEST, null));
            return;
        }
        this.settingsAdminIndex.putSettings(
                body,
                ActionListener.wrap(
                        response ->
                                listener.onResponse(
                                        new PutAiAssistantSettingsResponse("Settings updated.", RestStatus.OK, null)),
                        e -> {
                            log.error("Failed to update AI assistant settings: {}", e.getMessage(), e);
                            listener.onFailure(e);
                        }));
    }

    private void putProvider(
            PutAiAssistantSettingsRequest request,
            ActionListener<PutAiAssistantSettingsResponse> listener) {
        Map<String, Object> provider;
        try {
            provider = parseBody(request.getPayload());
        } catch (Exception e) {
            listener.onResponse(
                    new PutAiAssistantSettingsResponse(
                            "Invalid request body.", RestStatus.BAD_REQUEST, null));
            return;
        }

        // "id" is never a stored provider field; it only ever selects the target document.
        Object bodyId = provider.remove(ID_FIELD);
        String targetId = request.getProviderId();
        if (targetId == null || targetId.isBlank()) {
            // Creation (POST): the body must carry the id, and it must be a UUID.
            if (bodyId == null) {
                listener.onResponse(
                        new PutAiAssistantSettingsResponse(
                                "Provider id is required.", RestStatus.BAD_REQUEST, null));
                return;
            }
            String bodyIdString = String.valueOf(bodyId);
            if (!isValidUuid(bodyIdString)) {
                listener.onResponse(
                        new PutAiAssistantSettingsResponse(
                                "Provider id must be a valid UUID.", RestStatus.BAD_REQUEST, null));
                return;
            }
            targetId = bodyIdString;
        }

        if (AiAssistantSettingsAdminIndex.RESERVED_PROVIDER_IDS.contains(targetId)) {
            listener.onResponse(
                    new PutAiAssistantSettingsResponse(
                            "Provider id is reserved.", RestStatus.BAD_REQUEST, null));
            return;
        }

        this.settingsAdminIndex.putProvider(
                targetId,
                provider,
                ActionListener.wrap(
                        response ->
                                listener.onResponse(
                                        new PutAiAssistantSettingsResponse(
                                                "Provider saved.", RestStatus.OK, response.getId())),
                        e -> {
                            log.error("Failed to save AI assistant provider: {}", e.getMessage(), e);
                            listener.onFailure(e);
                        }));
    }

    private static boolean isValidUuid(String value) {
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private void deleteProvider(
            PutAiAssistantSettingsRequest request,
            ActionListener<PutAiAssistantSettingsResponse> listener) {
        String targetId = request.getProviderId();
        if (AiAssistantSettingsAdminIndex.RESERVED_PROVIDER_IDS.contains(targetId)) {
            listener.onResponse(
                    new PutAiAssistantSettingsResponse(
                            "Provider id is reserved.", RestStatus.BAD_REQUEST, null));
            return;
        }
        this.settingsAdminIndex.deleteProvider(
                targetId,
                ActionListener.wrap(
                        response ->
                                listener.onResponse(
                                        new PutAiAssistantSettingsResponse(
                                                "Provider deleted.", RestStatus.OK, targetId)),
                        e -> {
                            if (!(e instanceof ResourceNotFoundException)) {
                                log.error("Failed to delete AI assistant provider: {}", e.getMessage(), e);
                            }
                            listener.onFailure(e);
                        }));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseBody(String payload) throws Exception {
        JsonNode root = MAPPER.readTree(payload);
        return MAPPER.convertValue(root, Map.class);
    }
}
