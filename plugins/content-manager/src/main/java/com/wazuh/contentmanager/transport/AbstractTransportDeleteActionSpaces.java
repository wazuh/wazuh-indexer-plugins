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
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.ContentDeleteRequest;
import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
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
 * Abstract transport action for deleting content resources (Spaces variant).
 *
 * <p>Mirrors the business logic from {@code AbstractDeleteActionSpaces.executeRequest()}.
 */
public abstract class AbstractTransportDeleteActionSpaces
        extends HandledTransportAction<ContentDeleteRequest, ContentResponse> {

    private static final Logger log = LogManager.getLogger(AbstractTransportDeleteActionSpaces.class);
    protected final PayloadValidations documentValidations = new PayloadValidations();
    protected final Client client;
    protected final EngineService engine;

    protected AbstractTransportDeleteActionSpaces(
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
                            executeDeleteWorkflow(request, client, spaceService, listener);
                        },
                        e -> respondWithError(listener, request.getId(), e)));
    }

    private void executeDeleteWorkflow(
            ContentDeleteRequest request,
            Client client,
            SpaceService spaceService,
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

            // Validate document is in valid space
            String spaceError =
                    validateDocumentInSpace(client, this.getIndexName(), id, this.getResourceType());
            if (spaceError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Delete",
                        this.getResourceType(),
                        id,
                        "Resource is not in a valid space");
                respond(listener, new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus()));
                return;
            }
            final String spaceName = this.resolvedSpaceName;

            // 2. Pre-delete validation (async)
            this.validateDelete(
                    client,
                    id,
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
                                deleteExternalStep(client, id, index, spaceService, spaceName, listener);
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
            String spaceName,
            ActionListener<ContentResponse> listener) {
        // 3. External Sync (async)
        this.deleteExternalServices(
                id,
                ActionListener.wrap(
                        v -> unlinkStep(client, id, index, spaceService, spaceName, listener),
                        e -> {
                            if (this.isNotFoundException(e)) {
                                log.warn(Constants.W_LOG_EXTERNAL_NOT_FOUND, this.getResourceType(), id);
                                unlinkStep(client, id, index, spaceService, spaceName, listener);
                            } else {
                                log.error(
                                        Constants.E_LOG_FAILED_TO,
                                        "delete",
                                        this.getResourceType(),
                                        id,
                                        "from external service: " + e.getMessage());
                                respond(
                                        listener,
                                        new RestResponse(
                                                "Failed to delete from external service: " + e.getMessage(),
                                                RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                            }
                        }));
    }

    private void unlinkStep(
            Client client,
            String id,
            ContentIndex index,
            SpaceService spaceService,
            String spaceName,
            ActionListener<ContentResponse> listener) {
        // 4. Unlink Parent (async)
        this.unlinkFromParent(
                client,
                id,
                spaceName,
                ActionListener.wrap(
                        v -> {
                            // 5. Delete from Index
                            index.delete(id);

                            // 6. Hash Update (async)
                            spaceService.calculateAndUpdate(
                                    List.of(spaceName),
                                    ActionListener.wrap(
                                            changed -> {
                                                log.info(Constants.I_LOG_SUCCESS, "Deleted", this.getResourceType(), id);
                                                respond(listener, new RestResponse(id, RestStatus.OK.getStatus()));
                                            },
                                            e -> respondWithError(listener, id, e)));
                        },
                        e -> {
                            log.error(
                                    Constants.E_LOG_FAILED_TO,
                                    "unlink",
                                    this.getResourceType(),
                                    id,
                                    "from parent: " + e.getMessage());
                            respond(
                                    listener,
                                    new RestResponse(
                                            "Failed to unlink from parent: " + e.getMessage(),
                                            RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                        }));
    }

    private void respond(ActionListener<ContentResponse> listener, RestResponse result) {
        listener.onResponse(
                new ContentResponse(result.getMessage(), RestStatus.fromCode(result.getStatus())));
    }

    private void respondWithError(ActionListener<ContentResponse> listener, String id, Exception e) {
        OpenSearchSecurityException secEx = TransportActionHelper.extractSecurityException(e);
        if (secEx != null) {
            listener.onResponse(new ContentResponse(secEx.getMessage(), secEx.status()));
            return;
        }
        log.error(Constants.E_LOG_UNEXPECTED, "deleting", this.getResourceType(), id, e.getMessage());
        listener.onResponse(
                new ContentResponse(
                        "Internal Server Error. " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR));
    }

    private String resolvedSpaceName;

    private String validateDocumentInSpace(
            Client client, String index, String docId, String docType) {
        GetResponse response = client.prepareGet(index, docId).get();
        docType = Strings.capitalize(docType);

        if (!response.isExists()) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_NOT_FOUND, docType, docId);
        }

        Map<String, Object> source = response.getSourceAsMap();
        if (source == null || !source.containsKey(Constants.KEY_SPACE)) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_NOT_FOUND, docType, docId);
        }

        Object spaceObj = source.get(Constants.KEY_SPACE);
        if (!(spaceObj instanceof Map)) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_NOT_FOUND, docType, docId);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(Constants.KEY_NAME);
        this.resolvedSpaceName = String.valueOf(spaceName);

        if (!getAllowedSpaces().contains(Space.fromValue(this.resolvedSpaceName))) {
            return String.format(
                    Locale.ROOT, Constants.E_400_RESOURCE_SPACE_MISMATCH, this.getAllowedSpaces());
        }

        return null;
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

    protected abstract Set<Space> getAllowedSpaces();

    /**
     * Pre-delete validation hook. Implementations notify the listener with a non-null {@link
     * RestResponse} to abort the deletion, or {@code null} to proceed.
     */
    protected void validateDelete(Client client, String id, ActionListener<RestResponse> listener) {
        listener.onResponse(null);
    }

    protected abstract void deleteExternalServices(String id, ActionListener<Void> listener);

    protected abstract void unlinkFromParent(
            Client client, String id, String spaceName, ActionListener<Void> listener);
}
