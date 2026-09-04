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
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.List;

import com.wazuh.contentmanager.action.ContentDeleteRequest;
import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.MockSecurityAnalyticsService;

/**
 * Abstract transport action for deleting content resources (non-Spaces variant).
 *
 * <p>Mirrors the business logic from {@code AbstractDeleteAction.executeRequest()}. Resources are
 * always deleted from the DRAFT space.
 */
public abstract class AbstractTransportDeleteAction
        extends HandledTransportAction<ContentDeleteRequest, ContentResponse> {

    private static final Logger log = LogManager.getLogger(AbstractTransportDeleteAction.class);
    protected final PayloadValidations documentValidations = new PayloadValidations();
    protected final Client client;
    protected final EngineService engine;

    protected AbstractTransportDeleteAction(
            String actionName,
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(actionName, transportService, actionFilters, ContentDeleteRequest::new);
        this.client = client;
        this.engine = engine;
    }

    @Override
    protected void doExecute(
            Task task, ContentDeleteRequest request, ActionListener<ContentResponse> listener) {
        SecurityAnalyticsService securityAnalyticsService;
        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            securityAnalyticsService = new MockSecurityAnalyticsService();
        } else {
            securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        }
        SpaceService spaceService = new SpaceService(client);
        IntegrationService integrationService = new IntegrationService(client);

        TransportActionHelper.validateDraftPolicyExists(
                client,
                ActionListener.wrap(
                        policyError -> {
                            if (policyError != null) {
                                listener.onResponse(
                                        new ContentResponse(
                                                policyError.getMessage(), RestStatus.fromCode(policyError.getStatus())));
                                return;
                            }
                            executeDeleteWorkflow(
                                    request,
                                    client,
                                    spaceService,
                                    securityAnalyticsService,
                                    integrationService,
                                    listener);
                        },
                        e -> respondWithError(listener, request.getId(), e)));
    }

    private void executeDeleteWorkflow(
            ContentDeleteRequest request,
            Client client,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            IntegrationService integrationService,
            ActionListener<ContentResponse> listener) {
        String id = request.getId();

        try {
            // 1. Validation
            RestResponse validationError =
                    this.documentValidations.validateRequiredParam(id, Constants.KEY_ID);
            if (validationError != null) {
                respond(listener, validationError);
                return;
            }

            validationError = this.documentValidations.validateIdFormat(id, Constants.KEY_ID);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Delete",
                        this.getResourceType(),
                        id,
                        "Invalid ID format");
                respond(listener, validationError);
                return;
            }

            if (!client.admin().indices().prepareExists(this.getIndexName()).get().isExists()) {
                log.error(Constants.E_LOG_INDEX_NOT_FOUND, this.getIndexName());
                respond(
                        listener,
                        new RestResponse(
                                "Index not found: " + this.getIndexName(),
                                RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                return;
            }

            ContentIndex index = new ContentIndex(client, this.getIndexName(), null);
            if (!index.exists(id)) {
                log.warn(Constants.W_LOG_RESOURCE_NOT_FOUND, this.getResourceType(), id);
                respond(
                        listener,
                        new RestResponse(Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus()));
                return;
            }

            String spaceError =
                    this.documentValidations.validateDocumentInSpace(
                            client, this.getIndexName(), id, this.getResourceType());
            if (spaceError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Delete",
                        this.getResourceType(),
                        id,
                        "Resource is not in draft space");
                respond(listener, new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus()));
                return;
            }

            // 2. Pre-delete validation (async)
            this.validateDelete(
                    client,
                    id,
                    spaceService,
                    ActionListener.wrap(
                            preError -> {
                                if (preError != null) {
                                    log.warn(
                                            Constants.W_LOG_OPERATION_FAILED_ID,
                                            "Delete validation",
                                            this.getResourceType(),
                                            id,
                                            preError.getMessage());
                                    respond(listener, preError);
                                    return;
                                }
                                deleteExternalStep(
                                        client,
                                        id,
                                        index,
                                        spaceService,
                                        securityAnalyticsService,
                                        integrationService,
                                        listener);
                            },
                            e -> respondWithError(listener, id, e)));
        } catch (Exception e) {
            respondWithError(listener, id, e);
        }
    }

    private void deleteExternalStep(
            Client client,
            String id,
            ContentIndex index,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            IntegrationService integrationService,
            ActionListener<ContentResponse> listener) {
        // 3. External Sync (async)
        this.deleteExternalServices(
                id,
                securityAnalyticsService,
                ActionListener.wrap(
                        v -> unlinkStep(client, id, index, spaceService, integrationService, listener),
                        e -> {
                            if (this.isNotFoundException(e)) {
                                log.warn(Constants.W_LOG_EXTERNAL_NOT_FOUND, this.getResourceType(), id);
                                unlinkStep(client, id, index, spaceService, integrationService, listener);
                                return;
                            }
                            RestResponse classified = TransportActionHelper.classifyException(e);
                            if (classified != null) {
                                log.warn(
                                        Constants.E_LOG_FAILED_TO,
                                        "delete",
                                        this.getResourceType(),
                                        id,
                                        "from external service: " + classified.getMessage());
                                respond(listener, classified);
                                return;
                            }
                            log.error(
                                    Constants.E_LOG_FAILED_TO,
                                    "delete",
                                    this.getResourceType(),
                                    id,
                                    "from external service: " + e.getMessage());
                            respond(
                                    listener,
                                    new RestResponse(
                                            Constants.E_500_INTERNAL_SERVER_ERROR,
                                            RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                        }));
    }

    private void unlinkStep(
            Client client,
            String id,
            ContentIndex index,
            SpaceService spaceService,
            IntegrationService integrationService,
            ActionListener<ContentResponse> listener) {
        // 4. Unlink Parent (async)
        this.unlinkFromParent(
                client,
                id,
                integrationService,
                ActionListener.wrap(
                        v -> {
                            // 5. Delete from Index
                            index.delete(id);

                            // 6. Hash Update (async)
                            spaceService.calculateAndUpdate(
                                    List.of(Space.DRAFT.toString()),
                                    ActionListener.wrap(
                                            changed -> {
                                                log.info(Constants.I_LOG_SUCCESS, "Deleted", this.getResourceType(), id);
                                                respond(listener, new RestResponse(id, RestStatus.OK.getStatus()));
                                            },
                                            e -> respondWithError(listener, id, e)));
                        },
                        e -> {
                            RestResponse classified = TransportActionHelper.classifyException(e);
                            if (classified != null) {
                                log.warn(
                                        Constants.E_LOG_FAILED_TO,
                                        "unlink",
                                        this.getResourceType(),
                                        id,
                                        "from parent: " + classified.getMessage());
                                respond(listener, classified);
                                return;
                            }
                            log.error(
                                    Constants.E_LOG_FAILED_TO,
                                    "unlink",
                                    this.getResourceType(),
                                    id,
                                    "from parent: " + e.getMessage());
                            respond(
                                    listener,
                                    new RestResponse(
                                            Constants.E_500_INTERNAL_SERVER_ERROR,
                                            RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                        }));
    }

    private void respond(ActionListener<ContentResponse> listener, RestResponse result) {
        listener.onResponse(
                new ContentResponse(result.getMessage(), RestStatus.fromCode(result.getStatus())));
    }

    private void respondWithError(ActionListener<ContentResponse> listener, String id, Exception e) {
        RestResponse classified = TransportActionHelper.classifyException(e);
        if (classified != null) {
            log.warn(
                    Constants.W_LOG_OPERATION_FAILED,
                    "Deleting",
                    this.getResourceType(),
                    classified.getMessage());
            listener.onResponse(
                    new ContentResponse(
                            classified.getMessage(), RestStatus.fromCode(classified.getStatus())));
            return;
        }
        log.error(Constants.E_LOG_UNEXPECTED, "deleting", this.getResourceType(), id, e.getMessage());
        listener.onResponse(
                new ContentResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
    }

    private boolean isNotFoundException(Exception e) {
        Throwable cause = e;
        while (cause != null) {
            if (cause instanceof OpenSearchStatusException statusException) {
                if (statusException.status() == RestStatus.NOT_FOUND) {
                    return true;
                }
            }
            cause = cause.getCause();
        }
        return false;
    }

    protected abstract String getIndexName();

    protected abstract String getResourceType();

    /**
     * Pre-delete validation hook. Implementations notify the listener with a non-null {@link
     * RestResponse} to abort the deletion, or {@code null} to proceed.
     */
    protected void validateDelete(
            Client client, String id, SpaceService spaceService, ActionListener<RestResponse> listener) {
        listener.onResponse(null);
    }

    protected abstract void deleteExternalServices(
            String id, SecurityAnalyticsService securityAnalyticsService, ActionListener<Void> listener);

    protected abstract void unlinkFromParent(
            Client client,
            String id,
            IntegrationService integrationService,
            ActionListener<Void> listener);
}
