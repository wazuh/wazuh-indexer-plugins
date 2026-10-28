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
import org.opensearch.ExceptionsHelper;
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
import java.util.Map;
import java.util.UUID;

import com.wazuh.contentmanager.action.DeleteSpaceAction;
import com.wazuh.contentmanager.action.DeleteSpaceRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.ResourceLockService;
import com.wazuh.contentmanager.cti.catalog.service.ResourceLockTimeoutException;
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

    private final Client client;
    private final SpaceService spaceService;
    private final IntegrationService integrationService;
    private final SecurityAnalyticsService securityAnalyticsService;
    private final ResourceLockService resourceLockService;

    @Inject
    public TransportDeleteSpaceAction(
            TransportService transportService, ActionFilters actionFilters, Client client) {
        super(DeleteSpaceAction.NAME, transportService, actionFilters, DeleteSpaceRequest::new);
        this.client = client;
        this.spaceService = new SpaceService(client);
        this.integrationService = new IntegrationService(client);
        this.resourceLockService = new ResourceLockService(client, transportService.getThreadPool());
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

        // Serialize every mutation of a space (full reset and both scoped clears) behind one lock, so
        // two concurrent clears cannot leave an integration emptied but not removed. Released on
        // completion (success or failure); taken as the plugin, so the caller needs no extra privilege.
        this.resourceLockService.acquire(
                Constants.LOCK_TYPE_SPACE,
                space.toString(),
                ActionListener.wrap(
                        lockId ->
                                runScopedClear(
                                        request,
                                        space,
                                        ActionListener.runAfter(
                                                listener, () -> this.resourceLockService.release(lockId))),
                        e -> {
                            if (ExceptionsHelper.unwrap(e, ResourceLockTimeoutException.class) != null) {
                                log.warn(
                                        "Could not acquire the lock to clear space [{}]: {}", space, e.getMessage());
                                listener.onResponse(
                                        new MessageStatusResponse(
                                                Constants.E_429_SPACE_BUSY, RestStatus.TOO_MANY_REQUESTS));
                            } else {
                                respondWithError(listener, space, "lock", e);
                            }
                        }));
    }

    /** Dispatches the requested scope's clear or reset. Runs while holding the space lock. */
    private void runScopedClear(
            DeleteSpaceRequest request, Space space, ActionListener<MessageStatusResponse> listener) {
        switch (request.getScope()) {
            case NORMALIZATION:
                log.info("Starting normalization clear for space [{}]", space);
                SpaceClearer.clearNormalization(
                        this.client,
                        this.spaceService,
                        this.integrationService,
                        this.securityAnalyticsService,
                        space.toString(),
                        ActionListener.wrap(
                                v -> respondSuccess(listener, space, Constants.S_200_CLEAR_NORMALIZATION),
                                e -> respondWithError(listener, space, "clear normalization resources for", e)));
                return;
            case DETECTION:
                log.info("Starting detection clear for space [{}]", space);
                SpaceClearer.clearDetection(
                        this.client,
                        this.spaceService,
                        this.integrationService,
                        this.securityAnalyticsService,
                        space.toString(),
                        ActionListener.wrap(
                                v -> respondSuccess(listener, space, Constants.S_200_CLEAR_DETECTION),
                                e -> respondWithError(listener, space, "clear detection resources for", e)));
                return;
            case FULL:
            default:
                break;
        }

        log.info("Starting reset operation for space [{}]", space);

        // Read the policy's metadata first so the reset can preserve it: a reset must not wipe the
        // space's own title, author, description, etc. On a read failure, fall back to the default.
        this.spaceService.getPolicy(
                space.toString(),
                ActionListener.wrap(
                        policySource -> resetSpace(space, extractMetadata(policySource), listener),
                        e -> {
                            log.warn(
                                    "Could not read the policy metadata before resetting [{}]; using the default. {}",
                                    space,
                                    e.getMessage());
                            resetSpace(space, null, listener);
                        }));
    }

    /**
     * Runs the full reset chain: clear Security Analytics, clear the {@code wazuh-threatintel-*}
     * resources (including the policy document), and re-seed the policy, keeping {@code
     * preservedMetadata} if present.
     */
    private void resetSpace(
            Space space,
            Map<String, Object> preservedMetadata,
            ActionListener<MessageStatusResponse> listener) {
        // 1. Remove resources belonging to the space in Security Analytics.
        this.securityAnalyticsService.deleteSpaceResources(
                space,
                ActionListener.wrap(
                        sapResponse ->
                                // 2. Remove resources belonging to the space in the
                                // wazuh-threatintel-* indices.
                                this.spaceService.deleteSpaceResources(
                                        space,
                                        ActionListener.wrap(
                                                v -> {
                                                    // 3. Re-generate the policy for the space, keeping its metadata.
                                                    String sharedDocumentId =
                                                            UUID.nameUUIDFromBytes(
                                                                            "wazuh-default-policy".getBytes(StandardCharsets.UTF_8))
                                                                    .toString();
                                                    this.spaceService.initializeSpace(
                                                            space.toString(),
                                                            sharedDocumentId,
                                                            preservedMetadata,
                                                            ActionListener.wrap(
                                                                    v2 -> {
                                                                        String message =
                                                                                String.format(
                                                                                        Locale.ROOT, Constants.S_200_SPACE_RESET, space);
                                                                        log.info(message);
                                                                        listener.onResponse(
                                                                                new MessageStatusResponse(message, RestStatus.OK));
                                                                    },
                                                                    e -> respondWithError(listener, space, "reset", e)));
                                                },
                                                e -> respondWithError(listener, space, "reset", e))),
                        e -> respondWithError(listener, space, "reset", e)));
    }

    /** Extracts the {@code document.metadata} block from a raw policy {@code _source}, or null. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> extractMetadata(Map<String, Object> policySource) {
        if (policySource == null) {
            return null;
        }
        Object document = policySource.get(Constants.KEY_DOCUMENT);
        if (document instanceof Map == false) {
            return null;
        }
        Object metadata = ((Map<String, Object>) document).get(Constants.KEY_METADATA);
        return metadata instanceof Map ? (Map<String, Object>) metadata : null;
    }

    private void respondSuccess(
            ActionListener<MessageStatusResponse> listener, Space space, String template) {
        String message = String.format(Locale.ROOT, template, space);
        log.info(message);
        listener.onResponse(new MessageStatusResponse(message, RestStatus.OK));
    }

    private void respondWithError(
            ActionListener<MessageStatusResponse> listener, Space space, String operation, Exception e) {
        RestResponse classified = TransportActionHelper.classifyException(e);
        if (classified != null) {
            log.warn("Failed to {} space [{}]: {}", operation, space, classified.getMessage());
            listener.onResponse(
                    new MessageStatusResponse(
                            classified.getMessage(), RestStatus.fromCode(classified.getStatus())));
            return;
        }
        log.error("Failed to {} space [{}]: {}", operation, space, e.getMessage());
        listener.onResponse(
                new MessageStatusResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
    }
}
