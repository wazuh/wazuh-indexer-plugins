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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Abstract handler for creating new content resources.
 *
 * <p>Implements the standard workflow for creation:
 *
 * <ol>
 *   <li>Validates request body and structure.
 *   <li>Validates resource-specific constraints.
 *   <li>Generates ID and metadata (timestamps).
 *   <li>Synchronizes with external services (Engine/SAP).
 *   <li>Indexes the document in a valid space.
 *   <li>Links the resource to its parent (e.g., Integration).
 *   <li>Updates the policy hash.
 * </ol>
 */
public abstract class AbstractCreateActionSpaces extends AbstractContentAction {

    private static final Logger log = LogManager.getLogger(AbstractCreateActionSpaces.class);
    protected static final ObjectMapper MAPPER = new ObjectMapper();
    protected final PayloadValidations documentValidations = new PayloadValidations();

    /**
     * Constructs an instance of AbstractCreateActionSpaces with the specified Engine service.
     *
     * @param engine The {@link EngineService} used to interact with the Engine for resource
     *     validation and synchronization.
     */
    public AbstractCreateActionSpaces(EngineService engine) {
        super(engine);
    }

    /**
     * Executes the creation workflow for a new content resource.
     *
     * <p>This method implements the complete creation pipeline:
     *
     * <ol>
     *   <li>Validates that the request contains a non-empty body
     *   <li>Parses and validates the JSON payload structure
     *   <li>Performs resource-specific validation
     *   <li>Generates a unique ID and metadata (timestamps, enabled flag)
     *   <li>Synchronizes the resource with external services (Engine/SAP)
     *   <li>Indexes the resource in the configured space
     *   <li>Links the resource to its parent container
     *   <li>Updates the policy hash for the affected space
     * </ol>
     *
     * @param request The REST request containing the resource creation payload in JSON format.
     * @param client The OpenSearch client used for indexing and linking operations.
     * @return A {@link RestResponse} containing the newly created resource ID with HTTP 201 status on
     *     success, or an appropriate error response with error details on failure.
     */
    @Override
    protected RestResponse executeRequest(RestRequest request, Client client) {
        // 1. Validate Request Content
        RestResponse validationError = this.documentValidations.validateRequestHasContent(request);
        if (validationError != null) {
            log.warn(
                    Constants.W_LOG_OPERATION_FAILED,
                    "Creation",
                    this.getResourceType(),
                    "Request body is missing");
            return validationError;
        }

        try {
            JsonNode rootNode;
            try {
                rootNode = MAPPER.readTree(request.content().streamInput());
            } catch (IOException e) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED,
                        "Creation",
                        this.getResourceType(),
                        "Invalid JSON format. Reason: " + e.getMessage());
                return new RestResponse(
                        Constants.E_400_INVALID_REQUEST_BODY + e.getMessage(),
                        RestStatus.BAD_REQUEST.getStatus());
            }

            // 2. Validate Payload Structure
            validationError =
                    this.documentValidations.validateResourcePayload(rootNode, this.requiresIntegrationId());
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED,
                        "Payload structure validation",
                        this.getResourceType(),
                        validationError.getMessage());
                return validationError;
            }

            ObjectNode resourceNode = (ObjectNode) rootNode.get(Constants.KEY_RESOURCE);

            // 3. Resource Specific Validation
            validationError = this.validatePayload(client, rootNode, resourceNode);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED,
                        "Validation",
                        this.getResourceType(),
                        validationError.getMessage());
                return validationError;
            }

            // 4. Generate ID and Metadata
            String id = UUID.randomUUID().toString();
            resourceNode.put(Constants.KEY_ID, id);

            String currentTimestamp = this.getCurrentDate();
            Resource.setCreationTime(resourceNode, currentTimestamp);
            Resource.setLastModificationTime(resourceNode, currentTimestamp);
            Resource.nestMetadataFields(resourceNode);

            if (!resourceNode.has(Constants.KEY_ENABLED)) {
                resourceNode.put(Constants.KEY_ENABLED, true);
            }

            // 6. External Sync
            validationError = this.syncExternalServices(id, resourceNode);
            if (validationError != null) {
                log.error(
                        Constants.E_LOG_FAILED_TO,
                        "sync",
                        this.getResourceType(),
                        id,
                        "with external services (Engine/SAP). Reason: " + validationError.getMessage());
                return validationError;
            }

            // 7. Indexing
            ContentIndex index = new ContentIndex(client, this.getIndexName(), null);
            JsonNode ctiWrapper = new Resource().wrapResource(resourceNode, this.getSpaceName());

            index.create(id, ctiWrapper);

            // 8. Link to Parent
            try {
                this.linkToParent(client, id, rootNode);
            } catch (Exception e) {
                log.error(
                        Constants.E_LOG_FAILED_TO,
                        "link",
                        this.getResourceType(),
                        id,
                        "to parent resource. Rolling back. Reason: " + e.getMessage());
                index.delete(id);
                this.rollbackExternalServices(id);
                throw e;
            }

            // 9. Update Hash
            this.spaceService.calculateAndUpdate(List.of(this.getSpaceName()));

            log.info(Constants.I_LOG_SUCCESS, "Created", this.getResourceType(), id);
            return new RestResponse(id, RestStatus.CREATED.getStatus());

        } catch (Exception e) {
            log.error(
                    Constants.E_LOG_OPERATION_FAILED,
                    "creating",
                    this.getResourceType(),
                    "Reason: " + e.getMessage());
            return new RestResponse(
                    "Internal Server Error. " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Indicates if the creation payload requires a parent Integration ID.
     *
     * @return true by default (e.g., Rule, Decoder, KVDB), false if not (e.g., Integration).
     */
    protected boolean requiresIntegrationId() {
        return true;
    }

    /**
     * Returns the index name where the resource should be indexed.
     *
     * <p>This index is used for storing the resource documents in OpenSearch. Implementations must
     * return a valid and consistent index name for the resource type.
     *
     * @return The name of the OpenSearch index for this resource type.
     */
    protected abstract String getIndexName();

    /**
     * Returns the resource type identifier.
     *
     * <p>This is used for logging, error messages, and identification purposes throughout the
     * creation workflow.
     *
     * @return A human-readable string describing the resource type (e.g., "Rule", "Decoder",
     *     "Integration").
     */
    protected abstract String getResourceType();

    /**
     * Returns the space name where the resource should be organized.
     *
     * <p>A space represents a logical grouping of resources. This space name is used for indexing,
     * linking, and policy hash calculations.
     *
     * @return The name of the space to contain this resource.
     */
    protected abstract String getSpaceName();

    /**
     * Performs resource-specific validation on the payload.
     *
     * <p>This method allows subclasses to implement custom validation logic specific to their
     * resource type. It is called after structural validation but before ID generation and
     * persistence operations.
     *
     * @param client The OpenSearch client for accessing data if validation requires lookups.
     * @param root The root JSON node containing both resource and metadata.
     * @param resource The resource JSON node to validate.
     * @return null if the payload is valid, or a {@link RestResponse} with error details otherwise.
     */
    protected abstract RestResponse validatePayload(Client client, JsonNode root, JsonNode resource);

    /**
     * Synchronizes the new resource with external services (Engine validation or SAP upsert).
     *
     * <p>This method allows subclasses to integrate with external systems. It is called after
     * validation and ID generation but before indexing. If this method returns an error, the entire
     * creation workflow is rolled back.
     *
     * @param id The unique identifier generated for the new resource.
     * @param resource The resource JSON node to synchronize.
     * @return null if synchronization is successful, or a {@link RestResponse} with error details
     *     otherwise.
     */
    protected abstract RestResponse syncExternalServices(String id, JsonNode resource);

    /**
     * Reverts external service changes if subsequent steps fail.
     *
     * <p>This method is called during rollback scenarios when indexing or parent linking fails.
     * Implementations should clean up any changes made by {@link #syncExternalServices(String,
     * JsonNode)}.
     *
     * @param id The unique identifier of the resource to rollback.
     */
    protected void rollbackExternalServices(String id) {}

    /**
     * Links the newly created resource to its parent container (e.g., adding Rule ID to Integration).
     *
     * <p>This method establishes relationships between the newly created resource and its parent or
     * related resources. If this method throws an exception, the resource is automatically deleted
     * and external services are rolled back.
     *
     * @param client The OpenSearch client for updating parent resources.
     * @param id The unique identifier of the newly created resource.
     * @param root The root JSON node containing both resource and metadata.
     * @throws IOException If an I/O error occurs during parent linking operations.
     */
    protected abstract void linkToParent(Client client, String id, JsonNode root) throws IOException;
}
