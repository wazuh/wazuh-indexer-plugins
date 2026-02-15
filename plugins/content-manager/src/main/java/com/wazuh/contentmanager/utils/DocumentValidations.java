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

import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

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
 * <p>Error messages are normalized to follow the pattern: "[DocType] [ID] [action/state]." TODO get
 * rid of this class completely during refactors. No static methods. Use hierarchy instead.
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

        if (!Space.DRAFT.equals(String.valueOf(spaceName))) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_NOT_IN_DRAFT, docType, docId);
        }

        return null;
    }

    /**
     * Validates that a document with the same title does not already exist in the given space.
     *
     * @param client the OpenSearch client
     * @param indexName the index to search in
     * @param space the space to check
     * @param title the title to validate
     * @param currentId the ID of the current document (for updates), can be null for creation
     * @param resourceType the type of resource for error messages
     * @return a RestResponse with error if a duplicate is found, null otherwise
     */
    public static RestResponse validateDuplicateTitle(
            Client client,
            String indexName,
            String space,
            String title,
            String currentId,
            String resourceType) {
        try {
            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();

            sourceBuilder.query(
                    QueryBuilders.boolQuery()
                            .must(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space))
                            .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_TITLE, title)));
            sourceBuilder.size(1);
            // We only need the ID to compare
            sourceBuilder.fetchSource(false);

            searchRequest.source(sourceBuilder);
            SearchResponse response = client.search(searchRequest).actionGet();

            if (Objects.requireNonNull(response.getHits().getTotalHits()).value() > 0) {
                if (currentId != null) {
                    String foundId = response.getHits().getAt(0).getId();
                    if (foundId.equals(currentId)) {
                        return null;
                    }
                }
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_DUPLICATE_NAME, resourceType, title, space),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        } catch (Exception e) {
            return new RestResponse(
                    "Error validating duplicate name: " + e.getMessage(),
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
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
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
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
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, paramName),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates that a string is a valid UUID format.
     *
     * @param value the string value to validate as UUID
     * @return a RestResponse with error if validation fails, null otherwise
     */
    public static RestResponse validateUUID(String value) {
        try {
            java.util.UUID.fromString(value);
            return null;
        } catch (IllegalArgumentException e) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INVALID_UUID, value),
                    RestStatus.BAD_REQUEST.getStatus());
        }
    }

    /**
     * Validates the standard structure of a resource payload.
     *
     * @param payload The raw JSON payload.
     * @param requireIntegrationId If true, checks for 'integration' field (for Creates).
     * @return RestResponse if error, null if valid.
     */
    public static RestResponse validateResourcePayload(
            JsonNode payload, boolean requireIntegrationId) {
        // Validation for Integration ID presence
        if (requireIntegrationId) {
            if (!payload.has(Constants.KEY_INTEGRATION)
                    || payload.get(Constants.KEY_INTEGRATION).asText("").isBlank()) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_INTEGRATION),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        }

        // Validation for Resource object presence
        if (!payload.has(Constants.KEY_RESOURCE) || !payload.get(Constants.KEY_RESOURCE).isObject()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_RESOURCE),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        return null;
    }
}
