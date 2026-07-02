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
import org.opensearch.action.support.PlainActionFuture;
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
                () -> {
                    try {
                        RestResponse result =
                                executeDeleteWorkflow(request, client, spaceService, securityAnalyticsService);
                        listener.onResponse(
                                new ContentResponse(result.getMessage(), RestStatus.fromCode(result.getStatus())));
                    } catch (Exception e) {
                        listener.onResponse(
                                new ContentResponse(
                                        e.getMessage() != null ? e.getMessage() : "Unexpected error",
                                        RestStatus.INTERNAL_SERVER_ERROR));
                    }
                },
                policyError ->
                        listener.onResponse(
                                new ContentResponse(
                                        policyError.getMessage(), RestStatus.fromCode(policyError.getStatus()))));
    }

    private RestResponse executeDeleteWorkflow(
            ContentDeleteRequest request,
            Client client,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService) {
        String id = request.getId();
        String spaceName = null;

        try {
            // 1. Validation
            RestResponse validationError =
                    this.documentValidations.validateRequiredParam(id, Constants.KEY_ID);
            if (validationError != null) return validationError;

            validationError = this.documentValidations.validateIdFormat(id, Constants.KEY_ID);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Delete",
                        this.getResourceType(),
                        id,
                        "Invalid ID format");
                return validationError;
            }

            if (!client.admin().indices().prepareExists(this.getIndexName()).get().isExists()) {
                log.error(Constants.E_LOG_INDEX_NOT_FOUND, this.getIndexName());
                return new RestResponse(
                        "Index not found: " + this.getIndexName(),
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            ContentIndex index = new ContentIndex(client, this.getIndexName(), null);
            if (!index.exists(id)) {
                log.warn(Constants.W_LOG_RESOURCE_NOT_FOUND, this.getResourceType(), id);
                return new RestResponse(
                        Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
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
                return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());
            }
            spaceName = this.resolvedSpaceName;

            // 2. Pre-delete validation
            validationError = this.validateDelete(client, id);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Delete validation",
                        this.getResourceType(),
                        id,
                        validationError.getMessage());
                return validationError;
            }

            // 3. External Sync
            try {
                this.deleteExternalServices(id);
            } catch (Exception e) {
                if (this.isNotFoundException(e)) {
                    log.warn(Constants.W_LOG_EXTERNAL_NOT_FOUND, this.getResourceType(), id);
                } else {
                    log.error(
                            Constants.E_LOG_FAILED_TO,
                            "delete",
                            this.getResourceType(),
                            id,
                            "from external service: " + e.getMessage());
                    return new RestResponse(
                            "Failed to delete from external service: " + e.getMessage(),
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                }
            }

            // 4. Unlink Parent
            try {
                this.unlinkFromParent(client, id, spaceName);
            } catch (Exception e) {
                log.error(
                        Constants.E_LOG_FAILED_TO,
                        "unlink",
                        this.getResourceType(),
                        id,
                        "from parent: " + e.getMessage());
                return new RestResponse(
                        "Failed to unlink from parent: " + e.getMessage(),
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // 5. Delete from Index
            index.delete(id);

            // 6. Hash Update
            PlainActionFuture<Set<String>> hashFuture = new PlainActionFuture<>();
            spaceService.calculateAndUpdate(List.of(spaceName), hashFuture);
            hashFuture.actionGet();

            log.info(Constants.I_LOG_SUCCESS, "Deleted", this.getResourceType(), id);
            return new RestResponse(id, RestStatus.OK.getStatus());

        } catch (Exception e) {
            OpenSearchSecurityException secEx = TransportActionHelper.extractSecurityException(e);
            if (secEx != null) {
                return new RestResponse(secEx.getMessage(), secEx.status().getStatus());
            }
            log.error(Constants.E_LOG_UNEXPECTED, "deleting", this.getResourceType(), id, e.getMessage());
            return new RestResponse(
                    "Internal Server Error. " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
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

    protected RestResponse validateDelete(Client client, String id) {
        return null;
    }

    protected abstract void deleteExternalServices(String id);

    protected abstract void unlinkFromParent(Client client, String id, String spaceName)
            throws Exception;
}
