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
import com.wazuh.contentmanager.cti.catalog.model.Decoder;
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
 *   <li>Indexes the document in a space.
 *   <li>Links the resource to its parent (e.g., Integration).
 *   <li>Updates the policy hash.
 * </ol>
 */
public abstract class AbstractCreateActionSpaces extends AbstractContentAction {

    private static final Logger log = LogManager.getLogger(AbstractCreateActionSpaces.class);
    protected static final ObjectMapper MAPPER = new ObjectMapper();
    protected final PayloadValidations documentValidations = new PayloadValidations();

    public AbstractCreateActionSpaces(EngineService engine) {
        super(engine);
    }

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
            if (this.isDecoder()) {
                Decoder.setCreationTime(resourceNode, currentTimestamp);
                Decoder.setLastModificationTime(resourceNode, currentTimestamp);
            } else {
                Resource.setCreationTime(resourceNode, currentTimestamp);
                Resource.setLastModificationTime(resourceNode, currentTimestamp);
            }

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

            index.create(id, ctiWrapper, false);

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

    /** Indicates if the resource is a Decoder (requires special metadata handling). */
    protected boolean isDecoder() {
        return false;
    }

    protected abstract String getIndexName();

    protected abstract String getResourceType();

    protected abstract String getSpaceName();

    /**
     * Performs resource-specific validation on the payload.
     *
     * @return null if valid, RestResponse with error otherwise.
     */
    protected abstract RestResponse validatePayload(Client client, JsonNode root, JsonNode resource);

    /**
     * Synchronizes the new resource with external services (Engine validation or SAP upsert).
     *
     * @return null if successful, RestResponse with error otherwise.
     */
    protected abstract RestResponse syncExternalServices(String id, JsonNode resource);

    /** Reverts external service changes if subsequent steps fail. */
    protected void rollbackExternalServices(String id) {}

    /**
     * Links the newly created resource to its parent container (e.g., adding Rule ID to Integration).
     */
    protected abstract void linkToParent(Client client, String id, JsonNode root) throws IOException;
}
