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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import com.wazuh.contentmanager.action.LogtestResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Utility class providing common validation methods for REST handlers. */
public class PayloadValidations {

    private static final Logger log = LogManager.getLogger(PayloadValidations.class);

    private static final Pattern ID_PATTERN = Pattern.compile("^[a-zA-Z0-9-_]+$");

    /**
     * Transient thread-context key under which the OpenSearch security plugin stores the
     * authenticated user. Read reflectively (via {@code toString()}) so the plugin does not take a
     * hard compile dependency on the optional security plugin.
     */
    private static final String SECURITY_USER_TRANSIENT = "_opendistro_security_user";

    /** Public constructor to allow instantiation. */
    public PayloadValidations() {}

    /**
     * Enforces the configured maximum logtest request-body size, before the body is parsed or
     * dispatched to the transport layer. The raw byte length of the request content is checked (the
     * envelope around the {@code event} is negligible, so this bounds the event too). When the limit
     * is exceeded the offending call is logged with the responsible account so operators can
     * attribute abuse, and a {@code 413 REQUEST_ENTITY_TOO_LARGE} response is returned.
     *
     * @param request the incoming REST request.
     * @param maxBytes the maximum allowed body size in bytes.
     * @param threadContext the current thread context, used to resolve the authenticated user for the
     *     abuse log (may be null).
     * @return a {@link LogtestResponse} carrying the 413 error when the body is too large, or {@code
     *     null} when the body is within the limit.
     */
    public static LogtestResponse validateLogtestBodySize(
            RestRequest request, long maxBytes, ThreadContext threadContext) {
        int length = request.content().length();
        if (length > maxBytes) {
            Object userObj =
                    threadContext == null ? null : threadContext.getTransient(SECURITY_USER_TRANSIENT);
            String user = userObj == null ? "unknown" : userObj.toString();
            log.warn(
                    "Rejected oversized logtest request: {} bytes exceeds limit of {} bytes, path [{}], user [{}].",
                    length,
                    maxBytes,
                    request.path(),
                    user);
            return new LogtestResponse(
                    String.format(Locale.ROOT, Constants.E_413_LOGTEST_EVENT_TOO_LARGE, maxBytes),
                    RestStatus.REQUEST_ENTITY_TOO_LARGE);
        }
        return null;
    }

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
        FetchSourceContext spaceOnly =
                new FetchSourceContext(true, new String[] {Constants.Q_SPACE_NAME}, new String[0]);
        GetResponse response =
                client.get(new GetRequest(index, docId).fetchSourceContext(spaceOnly)).actionGet();
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
     * Checks whether an integration document is in {@code protected} mode. Protected integrations are
     * managed by Wazuh and cannot be modified or deleted through the API. The check relies on the
     * {@code document.mode} field so it stays correct regardless of the space the resource lives in.
     *
     * @param document the {@code document} node of the stored resource.
     * @return true if the resource is protected, false otherwise.
     */
    public boolean isProtected(JsonNode document) {
        return document != null
                && document.has(Constants.KEY_MODE)
                && Constants.MODE_PROTECTED.equals(document.get(Constants.KEY_MODE).asText());
    }

    /**
     * Asynchronously validates that a document exists and is in the draft space.
     *
     * @param client the OpenSearch client
     * @param index the index to search in
     * @param docId document ID to validate
     * @param docType the document type name for error messages
     * @param listener receives an error string if validation fails, null otherwise
     */
    public void validateDocumentInSpaceAsync(
            Client client, String index, String docId, String docType, ActionListener<String> listener) {
        String capitalizedDocType = Strings.capitalize(docType);
        FetchSourceContext spaceOnly =
                new FetchSourceContext(true, new String[] {Constants.Q_SPACE_NAME}, new String[0]);
        client.get(
                new GetRequest(index, docId).fetchSourceContext(spaceOnly),
                ActionListener.wrap(
                        response -> {
                            if (!response.isExists()) {
                                listener.onResponse(
                                        String.format(
                                                Locale.ROOT,
                                                Constants.E_400_RESOURCE_NOT_FOUND,
                                                capitalizedDocType,
                                                docId));
                                return;
                            }

                            Map<String, Object> source = response.getSourceAsMap();
                            if (source == null || !source.containsKey(Constants.KEY_SPACE)) {
                                listener.onResponse(
                                        String.format(
                                                Locale.ROOT,
                                                Constants.E_400_RESOURCE_NOT_FOUND,
                                                capitalizedDocType,
                                                docId));
                                return;
                            }

                            Object spaceObj = source.get(Constants.KEY_SPACE);
                            if (!(spaceObj instanceof Map)) {
                                listener.onResponse(
                                        String.format(
                                                Locale.ROOT,
                                                Constants.E_400_RESOURCE_NOT_FOUND,
                                                capitalizedDocType,
                                                docId));
                                return;
                            }

                            @SuppressWarnings("unchecked")
                            Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
                            Object spaceName = spaceMap.get(Constants.KEY_NAME);

                            if (!Space.DRAFT.equals(String.valueOf(spaceName))) {
                                listener.onResponse(
                                        String.format(
                                                Locale.ROOT,
                                                Constants.E_400_RESOURCE_NOT_IN_DRAFT,
                                                capitalizedDocType,
                                                docId));
                                return;
                            }

                            listener.onResponse(null);
                        },
                        listener::onFailure));
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

            // Query: space.name == space AND document.metadata.title == title
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
     * Asynchronously validates that a document with the same title does not already exist.
     *
     * @param client the OpenSearch client
     * @param indexName the index to search in
     * @param space the space to check
     * @param title the title to validate
     * @param currentId the ID of the current document (for updates), can be null for creation
     * @param resourceType the type of resource for error messages
     * @param listener receives a RestResponse with error if a duplicate is found, null otherwise
     */
    public void validateDuplicateTitleAsync(
            Client client,
            String indexName,
            String space,
            String title,
            String currentId,
            String resourceType,
            ActionListener<RestResponse> listener) {
        SearchRequest searchRequest = new SearchRequest(indexName);
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space))
                        .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_TITLE, title)));
        sourceBuilder.size(1);
        sourceBuilder.fetchSource(false);
        searchRequest.source(sourceBuilder);

        client.search(
                searchRequest,
                ActionListener.wrap(
                        response -> {
                            if (response.getHits().getTotalHits().value() > 0) {
                                if (currentId != null) {
                                    String foundId = response.getHits().getAt(0).getId();
                                    if (foundId.equals(currentId)) {
                                        listener.onResponse(null);
                                        return;
                                    }
                                }
                                listener.onResponse(
                                        new RestResponse(
                                                String.format(
                                                        Locale.ROOT,
                                                        Constants.E_400_DUPLICATE_NAME,
                                                        resourceType,
                                                        title,
                                                        space),
                                                RestStatus.BAD_REQUEST.getStatus()));
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        e ->
                                listener.onResponse(
                                        new RestResponse(
                                                "Error validating duplicate name: " + e.getMessage(),
                                                RestStatus.INTERNAL_SERVER_ERROR.getStatus()))));
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

        if (existingList.size() != incomingList.size() || !existingSet.equals(incomingSet)) {
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
     * @param knownEnrichmentTypes The list of known enrichment types to validate against.
     * @return A RestResponse error if validation fails, or null if valid.
     */
    public RestResponse validateEnrichments(
            List<String> enrichments, Set<String> knownEnrichmentTypes) {
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
            if (!knownEnrichmentTypes.contains(enrichment)) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_INVALID_ENRICHMENT, enrichment, knownEnrichmentTypes),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        }

        return null;
    }

    /**
     * Validates that a resource node contains a valid nested {@code metadata} block with required
     * fields. Checks that {@code title} is present and non-empty, and that {@code date} (if present)
     * is a valid ISO-8601 timestamp.
     *
     * @param resource The resource JSON node to validate.
     * @param requiredMetadataFields The metadata field names that must be present.
     * @return A RestResponse with an error if validation fails, or null if valid.
     */
    public RestResponse validateMetadataFields(
            JsonNode resource, List<String> requiredMetadataFields) {
        if (resource == null) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        if (!resource.has(Constants.KEY_METADATA) || !resource.get(Constants.KEY_METADATA).isObject()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_METADATA),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        JsonNode metadata = resource.get(Constants.KEY_METADATA);
        for (String field : requiredMetadataFields) {
            if (!metadata.has(field)) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, "metadata." + field),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            JsonNode node = metadata.get(field);
            if (node.isNull() || (node.isTextual() && node.asText().isBlank())) {
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, "metadata." + field),
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
