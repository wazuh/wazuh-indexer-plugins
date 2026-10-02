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
package com.wazuh.contentmanager.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;

import com.wazuh.contentmanager.action.DeleteSpaceAction;
import com.wazuh.contentmanager.action.DeleteSpaceRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.MockSecurityAnalyticsService;

public class TransportDeleteSpaceAction
        extends HandledTransportAction<DeleteSpaceRequest, MessageStatusResponse> {

    private static final Logger log = LogManager.getLogger(TransportDeleteSpaceAction.class);

    private final SpaceService spaceService;
    private final SecurityAnalyticsService securityAnalyticsService;

    @Inject
    public TransportDeleteSpaceAction(
            TransportService transportService, ActionFilters actionFilters, Client client) {
        super(DeleteSpaceAction.NAME, transportService, actionFilters, DeleteSpaceRequest::new);
        this.spaceService = new SpaceService(client);
        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            this.securityAnalyticsService = new MockSecurityAnalyticsService();
        } else {
            this.securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        }
    }

    @Override
    protected void doExecute(
            Task task, DeleteSpaceRequest request, ActionListener<MessageStatusResponse> listener) {
        String spaceParam = request.getSpaceName();

        Space space;
        try {
            space = Space.fromValue(spaceParam);
        } catch (IllegalArgumentException e) {
            listener.onResponse(
                    new MessageStatusResponse(
                            "Invalid space: [" + spaceParam + "].", RestStatus.BAD_REQUEST));
            return;
        }

        if (space != Space.DRAFT) {
            listener.onResponse(
                    new MessageStatusResponse(
                            "Cannot reset the '" + space + "' space.", RestStatus.BAD_REQUEST));
            return;
        }

        log.info("Starting reset operation for space [{}]", space);

        // 1. Remove resources belonging to the space in Security Analytics.
        this.securityAnalyticsService.deleteSpaceResources(
                space,
                ActionListener.wrap(
                        sapResponse -> {
                            // 2. Remove resources belonging to space in the wazuh-threatintel-*
                            // indices.
                            this.spaceService.deleteSpaceResources(
                                    space,
                                    ActionListener.wrap(
                                            v -> {
                                                // 3. Re-generate the default policy for the space
                                                String sharedDocumentId =
                                                        UUID.nameUUIDFromBytes(
                                                                        "wazuh-default-policy".getBytes(StandardCharsets.UTF_8))
                                                                .toString();
                                                this.spaceService.initializeSpace(
                                                        space.toString(),
                                                        sharedDocumentId,
                                                        ActionListener.wrap(
                                                                v2 -> {
                                                                    String message =
                                                                            String.format(
                                                                                    Locale.ROOT, "Successfully reset space [%s].", space);
                                                                    log.info(message);
                                                                    listener.onResponse(
                                                                            new MessageStatusResponse(message, RestStatus.OK));
                                                                },
                                                                e -> respondWithError(listener, space, e)));
                                            },
                                            e -> respondWithError(listener, space, e)));
                        },
                        e -> respondWithError(listener, space, e)));
    }

    private void respondWithError(
            ActionListener<MessageStatusResponse> listener, Space space, Exception e) {
        RestResponse classified = TransportActionHelper.classifyException(e);
        if (classified != null) {
            log.warn("Failed to reset space [{}]: {}", space, classified.getMessage());
            listener.onResponse(
                    new MessageStatusResponse(
                            classified.getMessage(), RestStatus.fromCode(classified.getStatus())));
            return;
        }
        log.error("Failed to reset space [{}]: {}", space, e.getMessage());
        listener.onResponse(
                new MessageStatusResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
    }
}
