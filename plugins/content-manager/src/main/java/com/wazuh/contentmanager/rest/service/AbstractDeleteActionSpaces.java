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
package com.wazuh.contentmanager.rest.service;

import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.get.GetResponse;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Abstract handler for deleting content resources.
 *
 * <p>Implements the standard workflow for deletion:
 *
 * <ol>
 *   <li>Validates ID presence and format.
 *   <li>Ensures the resource exists and is in the Draft space.
 *   <li>Performs pre-delete validation (e.g., checking for dependent resources).
 *   <li>Removes the resource from external services (Engine/SAP).
 *   <li>Unlinks the resource from its parent (Integration/Policy).
 *   <li>Deletes the document from the index.
 *   <li>Updates the policy hash.
 * </ol>
 */
public abstract class AbstractDeleteActionSpaces extends AbstractContentAction {

    private static final Logger log = LogManager.getLogger(AbstractDeleteActionSpaces.class);
    protected final PayloadValidations documentValidations = new PayloadValidations();

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);
    private String spaceName = "";

    public AbstractDeleteActionSpaces(EngineService engine) {
        super(engine);
    }

    @Override
    protected RestResponse executeRequest(RestRequest request, Client client) {
        String id = request.param(Constants.KEY_ID);

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
                this.unlinkFromParent(client, id);
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
            this.spaceService.calculateAndUpdate(List.of(this.getSpaceName()));

            log.info(Constants.I_LOG_SUCCESS, "Deleted", this.getResourceType(), id);
            return new RestResponse(id, RestStatus.OK.getStatus());

        } catch (Exception e) {
            log.error(Constants.E_LOG_UNEXPECTED, "deleting", this.getResourceType(), id, e.getMessage());
            return new RestResponse(
                    "Internal Server Error. " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    protected abstract String getIndexName();

    protected abstract String getResourceType();

    public void setSpaceName(String spaceName) {
        this.spaceName = spaceName;
    }

    public String getSpaceName() {
        return spaceName;
    }

    /**
     * Validates if the requested delete can be performed or not
     *
     * @param client Client used to search in the indices
     * @param id UUID of the resource to check
     * @return null if the resource can be deleted otherwise a RestResponse with the reason why it
     *     cannot
     */
    protected RestResponse validateDelete(Client client, String id) {
        return null;
    }

    /**
     * Synchronizes the deletion of the resource with external services (SAP).
     *
     * @param id Resource UUID
     */
    protected abstract void deleteExternalServices(String id);

    /**
     * Unlinks the just deleted resource to its parent container (e.g., deleting Rule ID to
     * Integration).
     */
    protected abstract void unlinkFromParent(Client client, String id) throws Exception;

    /**
     * Checks if the exception corresponds to a Not Found (404) error.
     *
     * @param e The exception to check.
     * @return true if it is a Not Found error, false otherwise.
     */
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

    /**
     * Validates that a document exists and is in a valid space.
     *
     * @param client the OpenSearch client
     * @param index the index to search in
     * @param docId document ID to validate
     * @param docType the document type name for error messages (e.g., "Decoder", "Integration")
     * @return an error message if validation fails, null otherwise
     */
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

        // validate that the space is one of the valid spaces for deletion (draft or standard)
        boolean match =
                AbstractDeleteActionSpaces.validSpaces.stream()
                        .anyMatch(space -> space.name().equalsIgnoreCase(String.valueOf(spaceName)));
        if (!match) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_SPACE_MISMATCH, validSpaces);
        }

        return null;
    }
}
