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
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Abstract handler for deleting content resources.
 *
 * <p>Implements the standard workflow for deletion:
 *
 * <ol>
 *   <li>Validates ID presence and format.
 *   <li>Ensures the resource exists and is in valid space.
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
    private String spaceName = null;

    /**
     * Constructs an instance of AbstractDeleteActionSpaces with the specified Engine service.
     *
     * @param engine The {@link EngineService} used to interact with the Engine for resource deletion
     *     and synchronization operations.
     */
    public AbstractDeleteActionSpaces(EngineService engine) {
        super(engine);
    }

    /**
     * Executes the deletion workflow for a content resource.
     *
     * <p>This method implements the complete deletion pipeline:
     *
     * <ol>
     *   <li>Validates that the resource ID is provided and in valid format
     *   <li>Confirms the index exists and the resource exists within it
     *   <li>Verifies the resource is in a valid space for deletion
     *   <li>Performs resource-specific pre-deletion validation
     *   <li>Removes the resource from external services (Engine/SAP)
     *   <li>Unlinks the resource from its parent container
     *   <li>Deletes the document from the OpenSearch index
     *   <li>Updates the policy hash for the affected space
     * </ol>
     *
     * @param request The REST request containing the resource ID as a path parameter.
     * @param client The OpenSearch client used for index operations and validation.
     * @return A {@link RestResponse} containing the deleted resource ID with HTTP 200 status on
     *     success, or an appropriate error response with error details on failure. Possible HTTP
     *     status codes:
     *     <ul>
     *       <li>200 OK: Resource deleted successfully.
     *       <li>400 Bad Request: ID is missing, invalid, or resource is in an invalid space.
     *       <li>404 Not Found: Index or resource ID not found.
     *       <li>500 Internal Server Error: Unexpected error during processing.
     *     </ul>
     */
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
                this.unlinkFromParent(client, id, this.spaceName);
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
            this.spaceService.calculateAndUpdate(List.of(this.spaceName));

            log.info(Constants.I_LOG_SUCCESS, "Deleted", this.getResourceType(), id);
            return new RestResponse(id, RestStatus.OK.getStatus());

        } catch (Exception e) {
            log.error(Constants.E_LOG_UNEXPECTED, "deleting", this.getResourceType(), id, e.getMessage());
            return new RestResponse(
                    "Internal Server Error. " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Returns the index name where the resource is stored.
     *
     * <p>This index is used for retrieving and deleting the resource documents in OpenSearch.
     * Implementations must return a valid and consistent index name for the resource type.
     *
     * @return The name of the OpenSearch index for this resource type.
     */
    protected abstract String getIndexName();

    /**
     * Returns the resource type identifier.
     *
     * <p>This is used for logging, error messages, and identification purposes throughout the
     * deletion workflow.
     *
     * @return A human-readable string describing the resource type (e.g., "Rule", "Decoder",
     *     "Filter").
     */
    protected abstract String getResourceType();

    /**
     * Returns the set of valid spaces where resources can be deleted.
     *
     * <p>This defines which spaces allow deletion operations. Resources in other spaces cannot be
     * deleted and will result in a validation error.
     *
     * @return A set of {@link Space} values representing the allowed spaces for deletion.
     */
    protected abstract Set<Space> getAllowedSpaces();

    /**
     * Validates if the requested deletion can be performed.
     *
     * <p>This method allows subclasses to implement resource-specific pre-deletion validation logic.
     * It is called after structural validation but before external service deletion. Common
     * validations might include checking for dependent resources or policy constraints.
     *
     * @param client The OpenSearch client for searching or accessing data if validation requires
     *     lookups.
     * @param id The unique identifier of the resource to validate for deletion.
     * @return null if the resource can be safely deleted, or a {@link RestResponse} with error
     *     details explaining why the deletion cannot proceed.
     */
    protected RestResponse validateDelete(Client client, String id) {
        return null;
    }

    /**
     * Removes the resource from external services (Engine/SAP).
     *
     * <p>This method is called during the deletion workflow to synchronize the resource removal with
     * external systems. If this method throws a NotFoundException, it will be logged as a warning but
     * will not fail the deletion. Other exceptions will cause the entire deletion to be rolled back.
     *
     * @param id The unique identifier of the resource to delete from external services.
     */
    protected abstract void deleteExternalServices(String id);

    /**
     * Unlinks the resource from its parent container.
     *
     * <p>This method is called during the deletion workflow to remove any parent-child relationships.
     * For example, when deleting a Rule, this method would remove the Rule ID from its parent
     * Integration. If this method throws an exception, the entire deletion is rolled back.
     *
     * @param client The OpenSearch client for updating parent resources.
     * @param id The unique identifier of the resource being unlinked from its parent.
     * @param spaceName The name of the space the resource belongs to, used for policy hash updates.
     * @throws Exception If an error occurs while unlinking from parent resources.
     */
    protected abstract void unlinkFromParent(Client client, String id, String spaceName)
            throws Exception;

    /**
     * Checks if the exception represents a Not Found (404) error.
     *
     * <p>This method traverses the exception cause chain to identify if the root cause is an
     * OpenSearchStatusException with a NOT_FOUND status. This is useful for distinguishing between
     * resource-not-found errors and other types of failures during external service deletion.
     *
     * @param e The exception to check.
     * @return true if the exception or any of its causes is an OpenSearchStatusException with
     *     NOT_FOUND status, false otherwise.
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
     * Validates that a document exists and is in a valid deletion space.
     *
     * <p>This method retrieves the document from the index and verifies:
     *
     * <ul>
     *   <li>The document exists in the index
     *   <li>The document has a valid space definition
     *   <li>The space is one of the allowed spaces for deletion
     * </ul>
     *
     * <p>If validation passes, the spaceName field is updated with the document's space name for use
     * in subsequent operations like policy hash updates.
     *
     * @param client The OpenSearch client for performing the document retrieval.
     * @param index The index name to search in.
     * @param docId The document ID to validate.
     * @param docType The document type name for error messages (e.g., "Decoder", "Integration").
     * @return An error message string if validation fails, null if validation succeeds.
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
        this.spaceName = String.valueOf(spaceName);

        // validate that the space is one of the valid spaces for deletion
        if (!getAllowedSpaces().contains(Space.fromValue(this.spaceName))) {
            return String.format(
                    Locale.ROOT, Constants.E_400_RESOURCE_SPACE_MISMATCH, this.getAllowedSpaces());
        }

        return null;
    }
}
