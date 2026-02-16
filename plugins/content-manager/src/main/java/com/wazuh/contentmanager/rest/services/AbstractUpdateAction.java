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
package com.wazuh.contentmanager.rest.services;

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

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.DocumentValidations;

/**
 * Abstract handler for updating existing content resources.
 *
 * <p>Implements the standard workflow for updates:
 *
 * <ol>
 *   <li>Validates ID presence and format.
 *   <li>Ensures the resource exists and is in the Draft space.
 *   <li>Validates payload structure and fields.
 *   <li>Updates timestamps (modified date).
 *   <li>Preserves immutable metadata (creation date, author details).
 *   <li>Synchronizes/Validates with external services.
 *   <li>Re-indexes the document and updates the hash.
 * </ol>
 */
public abstract class AbstractUpdateAction extends AbstractContentAction {

    private static final Logger log = LogManager.getLogger(AbstractUpdateAction.class);
    protected static final ObjectMapper MAPPER = new ObjectMapper();
    protected final DocumentValidations documentValidations = new DocumentValidations();

    public AbstractUpdateAction(EngineService engine) {
        super(engine);
    }

    @Override
    protected RestResponse executeRequest(RestRequest request, Client client) {
        // 1. Validate Request Content
        RestResponse validationError = this.documentValidations.validateRequestHasContent(request);
        if (validationError != null) {
            log.warn(
                    Constants.W_LOG_OPERATION_FAILED,
                    "Update",
                    this.getResourceType(),
                    "Request body is missing");
            return validationError;
        }

        String id = request.param(Constants.KEY_ID);

        try {
            // 2. Validate ID and Space
            validationError = this.documentValidations.validateRequiredParam(id, Constants.KEY_ID);
            if (validationError != null) return validationError;

            validationError = this.documentValidations.validateIdFormat(id, Constants.KEY_ID);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Update",
                        this.getResourceType(),
                        id,
                        "Invalid ID format");
                return validationError;
            }

            ContentIndex index = new ContentIndex(client, this.getIndexName(), null);
            if (!index.exists(id)) {
                log.warn(Constants.W_LOG_RESOURCE_NOT_FOUND, this.getResourceType(), id);
                return new RestResponse(
                        Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
            }

            String spaceError =
                    this.documentValidations.validateDocumentInSpace(
                            client, this.getIndexName(), id, this.getResourceType());
            if (spaceError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Update",
                        this.getResourceType(),
                        id,
                        "Resource is not in Draft space");
                return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());
            }

            // 3. Parse Body
            JsonNode rootNode;
            try {
                rootNode = MAPPER.readTree(request.content().streamInput());
            } catch (IOException e) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Update",
                        this.getResourceType(),
                        id,
                        "Invalid JSON format");
                return new RestResponse(
                        Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
            }

            // 4. Validate Payload
            validationError = this.documentValidations.validateResourcePayload(rootNode, false);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Payload validation",
                        this.getResourceType(),
                        id,
                        validationError.getMessage());
                return validationError;
            }

            ObjectNode resourceNode = (ObjectNode) rootNode.get(Constants.KEY_RESOURCE);
            resourceNode.put(Constants.KEY_ID, id);

            // 5. Resource Specific Validation
            validationError = this.validatePayload(client, rootNode, resourceNode);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Business logic validation",
                        this.getResourceType(),
                        id,
                        validationError.getMessage());
                return validationError;
            }

            // 6. Update Timestamps & Preserve Metadata
            this.contentUtils.updateTimestampMetadata(resourceNode, false, this.isDecoder());
            validationError = this.preserveMetadata(index, id, resourceNode);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Preserve metadata validation",
                        this.getResourceType(),
                        id,
                        validationError.getMessage());
                return validationError;
            }

            // 7. External Sync
            validationError = this.syncExternalServices(id, resourceNode);
            if (validationError != null) {
                log.error(
                        Constants.E_LOG_FAILED_TO,
                        "sync updated",
                        this.getResourceType(),
                        id,
                        "with external services. Reason: " + validationError.getMessage());
                return validationError;
            }

            // 8. Indexing
            JsonNode ctiWrapper = this.contentUtils.buildCtiWrapper(resourceNode, Space.DRAFT.toString());
            index.create(id, ctiWrapper, this.isDecoder());

            // 9. Update Hash
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            log.info(Constants.I_LOG_SUCCESS, "Updated", this.getResourceType(), id);
            return new RestResponse(id, RestStatus.OK.getStatus());

        } catch (Exception e) {
            log.error(Constants.E_LOG_UNEXPECTED, "updating", this.getResourceType(), id, e.getMessage());
            return new RestResponse(
                    "Internal Server Error. " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /** Indicates if the resource is a Decoder (requires special metadata handling). */
    protected boolean isDecoder() {
        return false;
    }

    /** Preserves creation date and other immutable fields from the existing document. */
    protected RestResponse preserveMetadata(ContentIndex index, String id, ObjectNode resourceNode) {
        JsonNode existingDoc = index.getDocument(id);
        if (existingDoc == null || !existingDoc.has(Constants.KEY_DOCUMENT)) return null;

        JsonNode doc = existingDoc.get(Constants.KEY_DOCUMENT);

        String date = null;
        if (this.isDecoder()) {
            if (doc.has(Constants.KEY_METADATA)
                    && doc.get(Constants.KEY_METADATA).has(Constants.KEY_AUTHOR)) {
                JsonNode auth = doc.get(Constants.KEY_METADATA).get(Constants.KEY_AUTHOR);
                if (auth.has(Constants.KEY_DATE)) date = auth.get(Constants.KEY_DATE).asText();
            }
        } else {
            if (doc.has(Constants.KEY_DATE)) date = doc.get(Constants.KEY_DATE).asText();
        }

        if (date != null) {
            if (this.isDecoder()) {
                if (resourceNode.has(Constants.KEY_METADATA)
                        && resourceNode.get(Constants.KEY_METADATA).has(Constants.KEY_AUTHOR)) {
                    ObjectNode author =
                            (ObjectNode) resourceNode.get(Constants.KEY_METADATA).get(Constants.KEY_AUTHOR);
                    author.put(Constants.KEY_DATE, date);
                }
            } else {
                resourceNode.put(Constants.KEY_DATE, date);
            }
        }

        if (!this.isDecoder() && !resourceNode.has(Constants.KEY_ENABLED)) {
            if (doc.has(Constants.KEY_ENABLED)) {
                resourceNode.put(Constants.KEY_ENABLED, doc.get(Constants.KEY_ENABLED).asBoolean());
            } else {
                resourceNode.put(Constants.KEY_ENABLED, true);
            }
        }
        return null;
    }

    protected abstract String getIndexName();

    protected abstract String getResourceType();

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
}
