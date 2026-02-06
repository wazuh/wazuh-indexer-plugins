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
package com.wazuh.contentmanager.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.get.GetResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static com.wazuh.contentmanager.utils.Constants.KEY_NAME;
import static com.wazuh.contentmanager.utils.Constants.KEY_SPACE;

/**
 * Utility class providing common validation methods for REST handlers.
 *
 * <p>This class centralizes validation logic for document operations, including:
 *
 * <ul>
 *   <li>Validating documents exist and are in draft space
 *   <li>Validating engine service availability
 *   <li>Validating request content presence
 *   <li>Validates the standard structure of a resource payload
 * </ul>
 *
 * <p>Error messages are normalized to follow the pattern: "[DocType] [ID] [action/state]."
 */
public class DocumentValidations {

    /** Private constructor to prevent instantiation. */
    private DocumentValidations() {}

    /**
     * Validates that a document exists and is in the draft space.
     *
     * @param client the OpenSearch client
     * @param index the index to search in
     * @param docId document ID to validate
     * @param docType the document type name for error messages (e.g., "Decoder", "Integration")
     * @return an error message if validation fails, null otherwise
     */
    public static String validateDocumentInSpace(
            Client client, String index, String docId, String docType) {
        GetResponse response = client.prepareGet(index, docId).get();

        if (!response.isExists()) {
            return docType + " [" + docId + "] not found.";
        }

        Map<String, Object> source = response.getSourceAsMap();
        if (source == null || !source.containsKey(KEY_SPACE)) {
            return docType + " [" + docId + "] does not have space information.";
        }

        Object spaceObj = source.get(KEY_SPACE);
        if (!(spaceObj instanceof Map)) {
            return docType + " [" + docId + "] has invalid space information.";
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(KEY_NAME);

        if (!Space.DRAFT.equals(String.valueOf(spaceName))) {
            return docType + " [" + docId + "] is not in draft space.";
        }

        return null;
    }

    /**
     * Validates that a document exists and is in the draft space. Returns a RestResponse on failure.
     *
     * <p>This method wraps {@link #validateDocumentInSpace} and returns a properly formatted
     * RestResponse with BAD_REQUEST status if validation fails.
     *
     * @param client the OpenSearch client
     * @param index the index to search in
     * @param docId document ID to validate
     * @param docType the document type name for error messages (e.g., "Decoder", "Integration")
     * @return a RestResponse with error if validation fails, null otherwise
     */
    public static RestResponse validateDocumentInSpaceWithResponse(
            Client client, String index, String docId, String docType) {
        String error = validateDocumentInSpace(client, index, docId, docType);
        if (error != null) {
            return new RestResponse(error, RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates that the engine service is available.
     *
     * @param engine the engine service to validate
     * @return a RestResponse with error if engine is unavailable, null otherwise
     */
    public static RestResponse validateEngineAvailable(EngineService engine) {
        if (engine == null) {
            return new RestResponse(
                    "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
        return null;
    }

    /**
     * Validates that the request has content (body).
     *
     * @param request the REST request to validate
     * @return a RestResponse with error if content is missing, null otherwise
     */
    public static RestResponse validateRequestHasContent(RestRequest request) {
        if (!request.hasContent()) {
            return new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates common prerequisites: engine availability and request content.
     *
     * <p>This is a convenience method combining engine and content validation.
     *
     * @param engine the engine service to validate
     * @param request the REST request to validate
     * @return a RestResponse with error if validation fails, null otherwise
     */
    public static RestResponse validatePrerequisites(EngineService engine, RestRequest request) {
        RestResponse error = validateEngineAvailable(engine);
        if (error != null) {
            return error;
        }
        return validateRequestHasContent(request);
    }

    /**
     * Validates that a required string parameter is present and not blank.
     *
     * @param value the parameter value to validate
     * @param paramName the name of the parameter for error messages
     * @return a RestResponse with error if validation fails, null otherwise
     */
    public static RestResponse validateRequiredParam(String value, String paramName) {
        if (value == null || value.isBlank()) {
            return new RestResponse(paramName + " is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates the standard structure of a resource payload.
     *
     * @param payload The raw JSON payload.
     * @param expectedId (Optional) The ID expected in the resource (for Updates).
     * @param requireIntegrationId If true, checks for 'integration' field (for Creates).
     * @return RestResponse if error, null if valid.
     */
    public static RestResponse validateResourcePayload(
            JsonNode payload, String expectedId, boolean requireIntegrationId) {
        // Validation for Integration ID presence
        if (requireIntegrationId) {
            if (!payload.has(Constants.KEY_INTEGRATION)
                    || payload.get(Constants.KEY_INTEGRATION).asText("").isBlank()) {
                return new RestResponse("Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
            }
        }

        // Validation for Resource object presence
        if (!payload.has(Constants.KEY_RESOURCE) || !payload.get(Constants.KEY_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }

        // Validation for Resource ID
        if (expectedId != null) {
            // For updates: ID in payload must match path ID
            ObjectNode resourceNode = (ObjectNode) payload.get(Constants.KEY_RESOURCE);
            if (resourceNode.hasNonNull(Constants.KEY_ID)) {
                String payloadId = resourceNode.get(Constants.KEY_ID).asText();
                if (!payloadId.equals(expectedId)) {
                    return new RestResponse(
                            "Resource ID does not match resource ID.", RestStatus.BAD_REQUEST.getStatus());
                }
            }
        } else {
            // For creates: Resource ID should typically not be provided by user
            if (payload.get(Constants.KEY_RESOURCE).hasNonNull(Constants.KEY_ID)) {
                return new RestResponse(
                        "Resource ID must not be provided on create.", RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }
}
