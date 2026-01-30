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
package com.wazuh.contentmanager.rest.helpers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;

import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static com.wazuh.contentmanager.utils.ContentManagerConstants.*;

/**
 * Helper class for integration-related operations in Content Manager.
 */
public final class IntegrationHelper {

    private IntegrationHelper() {
        // Utility class, prevent instantiation
    }

    /**
     * Updates the integration document to add a resource reference.
     *
     * @param client the OpenSearch client
     * @param integrationId the integration ID to update
     * @param resourceId the resource ID to add
     * @param fieldName the field name to update (e.g., "decoders", "kvdbs")
     * @param resourceType the type of resource being added (for error messages)
     * @throws IOException if an error occurs during the update
     */
    @SuppressWarnings("unchecked")
    public static void addResourceToIntegration(
            Client client,
            String integrationId,
            String resourceId,
            String fieldName,
            String resourceType) throws IOException {

        GetResponse integrationResponse = client.prepareGet(INTEGRATION_INDEX, integrationId).get();

        if (!integrationResponse.isExists()) {
            throw new IOException(
                    "Integration ["
                            + integrationId
                            + "] not found when creating "
                            + resourceType
                            + " ["
                            + resourceId
                            + "].");
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(FIELD_DOCUMENT)) {
            throw new IOException(
                    "Can't find document in integration ["
                            + integrationId
                            + "] when creating "
                            + resourceType
                            + " ["
                            + resourceId
                            + "].");
        }

        Object documentObj = source.get(FIELD_DOCUMENT);
        if (documentObj == null || !(documentObj instanceof Map)) {
            throw new IOException(
                    "Integration document ["
                            + integrationId
                            + "] is invalid when creating "
                            + resourceType
                            + " ["
                            + resourceId
                            + "].");
        }

        Map<String, Object> document = new HashMap<>((Map<String, Object>) documentObj);
        List<String> resources = extractListFromField(document.get(fieldName));

        if (!resources.contains(resourceId)) {
            resources.add(resourceId);
        }

        document.put(fieldName, resources);
        source.put(FIELD_DOCUMENT, document);

        client
                .index(
                        new IndexRequest(INTEGRATION_INDEX)
                                .id(integrationId)
                                .source(source)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }

    /**
     * Extracts a list of strings from a field, handling type conversion.
     *
     * @param existing the existing field value
     * @return a mutable list of strings
     */
    public static List<String> extractListFromField(Object existing) {
        List<String> result = new ArrayList<>();
        if (existing instanceof List) {
            for (Object item : (List<?>) existing) {
                result.add(String.valueOf(item));
            }
        }
        return result;
    }

    /**
     * Validates that the integration exists and is in the draft space.
     *
     * @param client the OpenSearch client
     * @param integrationId the integration ID to validate
     * @return a RestResponse with error if validation fails, null otherwise
     */
    public static RestResponse validateIntegrationSpace(Client client, String integrationId) {
        GetResponse integrationResponse = client.prepareGet(INTEGRATION_INDEX, integrationId).get();

        if (!integrationResponse.isExists()) {
            return new RestResponse(
                    "Integration [" + integrationId + "] not found.", RestStatus.BAD_REQUEST.getStatus());
        }

        Map<String, Object> source = integrationResponse.getSourceAsMap();
        if (source == null || !source.containsKey(FIELD_SPACE)) {
            return new RestResponse(
                    "Integration [" + integrationId + "] does not have space information.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        Object spaceObj = source.get(FIELD_SPACE);
        if (!(spaceObj instanceof Map)) {
            return new RestResponse(
                    "Integration [" + integrationId + "] has invalid space information.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(FIELD_NAME);

        if (!Space.DRAFT.equals(String.valueOf(spaceName))) {
            return new RestResponse(
                    "Integration ["
                            + integrationId
                            + "] is not in draft space. Only integrations in draft space can have resources created.",
                    RestStatus.BAD_REQUEST.getStatus());
        }

        return null;
    }

    /**
     * Validates that the engine service and request content are available.
     *
     * @param engine the engine service to validate
     * @param request the REST request to validate
     * @return a RestResponse with error if validation fails, null otherwise
     */
    public static RestResponse validatePrerequisites(EngineService engine, RestRequest request) {
        if (engine == null) {
            return new RestResponse(
                    "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
        if (!request.hasContent()) {
            return new RestResponse("JSON request body is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates the payload structure and required fields.
     *
     * @param payload the JSON payload to validate
     * @return a RestResponse with error if validation fails, null otherwise
     */
    public static RestResponse validatePayload(JsonNode payload) {
        if (!payload.has(FIELD_INTEGRATION) || payload.get(FIELD_INTEGRATION).asText("").isBlank()) {
            return new RestResponse("Integration ID is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        if (!payload.has(FIELD_RESOURCE) || !payload.get(FIELD_RESOURCE).isObject()) {
            return new RestResponse("Resource payload is required.", RestStatus.BAD_REQUEST.getStatus());
        }
        if (payload.get(FIELD_RESOURCE).hasNonNull(FIELD_ID)) {
            return new RestResponse(
                    "Resource ID must not be provided on create.", RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Validates the resource with the engine service.
     *
     * @param engine the engine service
     * @param resourceNode the resource node to validate
     * @param resourceType the type of resource (e.g., "decoder", "kvdb")
     * @return a RestResponse with error if validation fails, null otherwise (null means validation passed)
     */
    public static RestResponse validateWithEngine(
            EngineService engine, ObjectNode resourceNode, String resourceType) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode enginePayload = mapper.createObjectNode();
        enginePayload.put(FIELD_TYPE, resourceType);
        enginePayload.set(FIELD_RESOURCE, resourceNode);

        RestResponse response = engine.validate(enginePayload);
        if (response == null) {
            return new RestResponse(
                    "Invalid " + resourceType + " body, engine validation failed.",
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Adds or updates timestamp metadata to the resource node.
     *
     * @param mapper the ObjectMapper instance for creating nodes
     * @param resourceNode the resource node to update
     * @param isCreate true if creating (sets both date and modified), false if updating (sets only modified)
     * @param existingMetadata optional existing metadata from the stored document to preserve date on updates
     */
    public static void addTimestampMetadata(ObjectMapper mapper, ObjectNode resourceNode, boolean isCreate, ObjectNode existingMetadata) {
        String currentTimestamp = Instant.now().toString();

        // Ensure metadata node exists
        ObjectNode metadataNode;
        if (resourceNode.has(FIELD_METADATA) && resourceNode.get(FIELD_METADATA).isObject()) {
            metadataNode = (ObjectNode) resourceNode.get(FIELD_METADATA);
        } else {
            metadataNode = mapper.createObjectNode();
            resourceNode.set(FIELD_METADATA, metadataNode);
        }

        // Ensure author node exists
        ObjectNode authorNode;
        if (metadataNode.has(FIELD_AUTHOR) && metadataNode.get(FIELD_AUTHOR).isObject()) {
            authorNode = (ObjectNode) metadataNode.get(FIELD_AUTHOR);
        } else {
            authorNode = mapper.createObjectNode();
            metadataNode.set(FIELD_AUTHOR, authorNode);
        }

        // Set timestamps
        if (isCreate) {
            // On create, set both date and modified
            authorNode.put(FIELD_DATE, currentTimestamp);
        } else {
            // On update, preserve existing date if available
            if (existingMetadata != null && existingMetadata.has(FIELD_AUTHOR)) {
                JsonNode existingAuthor = existingMetadata.get(FIELD_AUTHOR);
                if (existingAuthor.has(FIELD_DATE)) {
                    authorNode.set(FIELD_DATE, existingAuthor.get(FIELD_DATE));
                }
            }
        }
        authorNode.put(FIELD_MODIFIED, currentTimestamp);
    }
}
