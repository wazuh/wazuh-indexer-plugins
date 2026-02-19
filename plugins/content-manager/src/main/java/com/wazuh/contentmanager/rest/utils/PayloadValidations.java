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
package com.wazuh.contentmanager.rest.utils;

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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Utility class providing common validation methods for REST handlers. */
public class PayloadValidations {

    private static final Pattern ID_PATTERN = Pattern.compile("^[a-zA-Z0-9-_]+$");

    /** Public constructor to allow instantiation. */
    public PayloadValidations() {}

    /**
     * Validates that a document exists and is in the draft space.
     *
     * @param client the OpenSearch client
     * @param index the index to search in
     * @param docId document ID to validate
     * @param docType the document type name for error messages (e.g., "Decoder", "Integration")
     * @return an error message if validation fails, null otherwise
     */
    public String validateDocumentInSpace(Client client, String index, String docId, String docType) {
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
    public RestResponse validateDuplicateTitle(
            Client client,
            String indexName,
            String space,
            String title,
            String currentId,
            String resourceType) {
        try {
            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();

            // Query: space.name == space AND document.title == title
            sourceBuilder.query(
                    QueryBuilders.boolQuery()
                            .must(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space))
                            .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_TITLE, title)));
            sourceBuilder.size(1);
            // We only need the ID to compare
            sourceBuilder.fetchSource(false);

            searchRequest.source(sourceBuilder);
            SearchResponse response = client.search(searchRequest).actionGet();

            if (response.getHits().getTotalHits().value() > 0) {
                // If checking for updates, ensure the found doc is not the one we are updating
                if (currentId != null) {
                    String foundId = response.getHits().getAt(0).getId();
                    if (foundId.equals(currentId)) {
                        return null; // Same document, no conflict
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
     * Validates that the engine service is available.
     *
     * @param engine the engine service to validate
     * @return a RestResponse with error if engine is unavailable, null otherwise
     */
    public RestResponse validateEngineAvailable(EngineService engine) {
        if (engine == null) {
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
        return null;
    }

    /**
     * Validates that the request has content (body).
     *
     * @param request the REST request to validate
     * @return a RestResponse with error if content is missing, null otherwise
     */
    public RestResponse validateRequestHasContent(RestRequest request) {
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
    public RestResponse validateRequiredParam(String value, String paramName) {
        if (value == null || value.isBlank()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, paramName),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates that the ID contains only safe characters (alphanumeric, hyphens, underscores).
     *
     * @param value the string value to validate
     * @param fieldName the name of the field being validated
     * @return a RestResponse with error if validation fails, null otherwise
     */
    public RestResponse validateIdFormat(String value, String fieldName) {
        if (value == null || !ID_PATTERN.matcher(value).matches()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_INVALID_FIELD_FORMAT, fieldName),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates the standard structure of a resource payload.
     *
     * @param payload The raw JSON payload.
     * @param requireIntegrationId If true, checks for 'integration' field (for Creates).
     * @return RestResponse if error, null if valid.
     */
    public RestResponse validateResourcePayload(JsonNode payload, boolean requireIntegrationId) {
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

    /**
     * Validates that the provided JSON node contains specific mandatory fields. Checks if the field
     * exists and is not null. For text fields, it also checks if they are blank. Objects and Arrays
     * are considered valid if they exist and are not null.
     *
     * @param resource The JSON node to validate (usually the 'resource' object).
     * @param requiredFields A list of keys that must be present.
     * @return A RestResponse with an error if a field is missing or invalid, or null if valid.
     */
    public RestResponse validateRequiredFields(JsonNode resource, List<String> requiredFields) {
        if (resource == null) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        for (String field : requiredFields) {
            if (!resource.has(field)) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, field),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            JsonNode node = resource.get(field);
            if (node.isNull() || (node.isTextual() && node.asText().isBlank())) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, field),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }

    /**
     * Validates that two lists contain the same set of elements, ignoring order. Used to ensure that
     * referenced resources (like rules or decoders) are not added or removed during specific updates.
     *
     * @param existingList The original list of strings.
     * @param incomingList The new list of strings.
     * @param fieldName The name of the field for error reporting.
     * @return A RestResponse error if the sets differ, or null if they are equal.
     */
    public RestResponse validateListEquality(
            List<String> existingList, List<String> incomingList, String fieldName) {
        Set<String> existingSet =
                new HashSet<>(existingList != null ? existingList : Collections.emptyList());
        Set<String> incomingSet =
                new HashSet<>(incomingList != null ? incomingList : Collections.emptyList());

        if (!existingSet.equals(incomingSet)) {
            return new RestResponse(
                    "Content of '"
                            + fieldName
                            + "' cannot be added or removed via update. Please use the specific resource endpoints.",
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates enrichment types in a policy. Enrichments can be added, removed, or reordered, but
     * only allowed values are accepted and duplicates are not permitted.
     *
     * @param enrichments The list of enrichment types to validate.
     * @return A RestResponse error if validation fails, or null if valid.
     */
    public RestResponse validateEnrichments(List<String> enrichments) {
        if (enrichments == null || enrichments.isEmpty()) {
            return null;
        }

        Set<String> seen = new HashSet<>();
        for (String enrichment : enrichments) {
            // Check for duplicates
            if (!seen.add(enrichment)) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_DUPLICATE_ENRICHMENT, enrichment),
                        RestStatus.BAD_REQUEST.getStatus());
            }

            // Check for invalid values
            if (!Constants.ALLOWED_ENRICHMENT_TYPES.contains(enrichment)) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_INVALID_ENRICHMENT, enrichment),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        }

        return null;
    }

    /**
     * Extracts a list of strings from a JSON node.
     *
     * @param parentNode The parent JSON node containing the list.
     * @param key The key of the list field.
     * @return A List of strings extracted from the JSON array.
     * @throws IllegalArgumentException If the field exists but is not an array.
     */
    public List<String> extractStringList(JsonNode parentNode, String key) {
        List<String> list = new ArrayList<>();
        if (parentNode.has(key)) {
            JsonNode node = parentNode.get(key);
            if (node.isArray()) {
                for (JsonNode item : node) {
                    list.add(item.asText());
                }
            } else {
                throw new IllegalArgumentException("Field '" + key + "' must be an array.");
            }
        }
        return list;
    }
}
