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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.rest.model.RestResponse;

/** Common utility methods for Content Manager REST actions. */
public class ContentUtils {

    private static final Logger log = LogManager.getLogger(ContentUtils.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    private ContentUtils() {}

    /**
     * Adds or updates timestamp metadata (date, modified) and author structure in the resource node.
     *
     * @param resourceNode The resource object to update.
     * @param isCreate If true, sets creation 'date'. Always sets 'modified'.
     */
    public static void updateTimestampMetadata(ObjectNode resourceNode, boolean isCreate) {
        String currentTimestamp = Instant.now().toString();

        // Ensure metadata node exists
        ObjectNode metadataNode;
        if (resourceNode.has(Constants.KEY_METADATA)
                && resourceNode.get(Constants.KEY_METADATA).isObject()) {
            metadataNode = (ObjectNode) resourceNode.get(Constants.KEY_METADATA);
        } else {
            metadataNode = mapper.createObjectNode();
            resourceNode.set(Constants.KEY_METADATA, metadataNode);
        }

        // Ensure author node exists
        ObjectNode authorNode;
        if (metadataNode.has(Constants.KEY_AUTHOR)
                && metadataNode.get(Constants.KEY_AUTHOR).isObject()) {
            authorNode = (ObjectNode) metadataNode.get(Constants.KEY_AUTHOR);
        } else {
            authorNode = mapper.createObjectNode();
            metadataNode.set(Constants.KEY_AUTHOR, authorNode);
        }

        // Set timestamps
        if (isCreate) {
            authorNode.put(Constants.KEY_DATE, currentTimestamp);
        }
        authorNode.put(Constants.KEY_MODIFIED, currentTimestamp);
    }

    /**
     * Validates that the metadata.author structure does not contain date or modified fields.
     *
     * @param resourceNode The resource JSON node.
     * @return RestResponse if validation fails, null otherwise.
     */
    public static RestResponse validateMetadataFields(JsonNode resourceNode) {
        if (resourceNode.has(Constants.KEY_METADATA)) {
            JsonNode metadata = resourceNode.get(Constants.KEY_METADATA);
            if (metadata.has(Constants.KEY_AUTHOR)) {
                JsonNode author = metadata.get(Constants.KEY_AUTHOR);
                if (author.has(Constants.KEY_DATE) || author.has(Constants.KEY_MODIFIED)) {
                    return new RestResponse(
                            "Fields 'metadata.author.date' and 'metadata.author.modified' are managed by the system.",
                            RestStatus.BAD_REQUEST.getStatus());
                }
            }
        }
        return null;
    }

    /**
     * Builds the standard CTI wrapper payload containing type, document, space, and hash.
     *
     * @param type The resource type (e.g., "decoder", "kvdb").
     * @param resourceNode The content of the resource.
     * @param spaceName The space name (e.g., "draft").
     * @return The constructed JsonNode wrapper.
     */
    public static JsonNode buildCtiWrapper(String type, JsonNode resourceNode, String spaceName) {
        ObjectNode wrapper = mapper.createObjectNode();
        wrapper.put(Constants.KEY_TYPE, type);
        wrapper.set(Constants.KEY_DOCUMENT, resourceNode);

        // Space
        ObjectNode space = mapper.createObjectNode();
        space.put(Constants.KEY_NAME, spaceName);
        wrapper.set(Constants.KEY_SPACE, space);

        // Hash
        String hash = HashCalculator.sha256(resourceNode.toString());
        ObjectNode hashNode = mapper.createObjectNode();
        hashNode.put(Constants.KEY_SHA256, hash);
        wrapper.set(Constants.KEY_HASH, hashNode);

        return wrapper;
    }

    /**
     * Links a resource to an integration by adding its ID to the specified list field.
     *
     * @param client OpenSearch client.
     * @param integrationId The ID of the integration to update.
     * @param resourceId The ID of the resource to link.
     * @param listKey The key of the list field in the integration document (e.g., "rules").
     * @throws IOException If the integration cannot be found or updated.
     */
    @SuppressWarnings("unchecked")
    public static void linkResourceToIntegration(
            Client client, String integrationId, String resourceId, String listKey) throws IOException {
        GetResponse response = client.prepareGet(Constants.INDEX_INTEGRATIONS, integrationId).get();

        if (!response.isExists()) {
            throw new IOException("Integration [" + integrationId + "] not found.");
        }

        Map<String, Object> source = response.getSourceAsMap();
        Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);

        List<String> list = (List<String>) document.getOrDefault(listKey, new ArrayList<>());

        // Ensure list is mutable
        if (!(list instanceof ArrayList)) {
            list = new ArrayList<>(list);
        }

        if (!list.contains(resourceId)) {
            list.add(resourceId);
            document.put(listKey, list);
            updateIntegrationSource(client, integrationId, document, source);
        }
    }

    /**
     * Unlinks a resource from all integrations that reference it.
     *
     * @param client OpenSearch client.
     * @param resourceId The ID of the resource to unlink.
     * @param listKey The key of the list field in the integration document (e.g., "rules").
     */
    public static void unlinkResourceFromIntegrations(
            Client client, String resourceId, String listKey) {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_INTEGRATIONS);
        searchRequest
                .source()
                .query(QueryBuilders.termQuery(Constants.KEY_DOCUMENT + "." + listKey, resourceId));

        try {
            SearchResponse searchResponse = client.search(searchRequest).actionGet();
            for (SearchHit hit : searchResponse.getHits().getHits()) {
                Map<String, Object> source = hit.getSourceAsMap();
                @SuppressWarnings("unchecked")
                Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);

                @SuppressWarnings("unchecked")
                List<String> list = (List<String>) document.get(listKey);

                if (list != null) {
                    List<String> updatedList = new ArrayList<>(list);
                    if (updatedList.remove(resourceId)) {
                        document.put(listKey, updatedList);
                        updateIntegrationSource(client, hit.getId(), document, source);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error unlinking resource [{}] from integrations: {}", resourceId, e.getMessage());
        }
    }

    /**
     * Updates the integration document in the index with a recalculated hash.
     *
     * @param client OpenSearch client.
     * @param id Integration ID.
     * @param document The updated document content.
     * @param source The full source map including metadata.
     * @throws IOException If indexing fails.
     */
    public static void updateIntegrationSource(
            Client client, String id, Map<String, Object> document, Map<String, Object> source)
            throws IOException {
        JsonNode documentNode = mapper.valueToTree(document);
        String newHash = HashCalculator.sha256(documentNode.toString());

        Map<String, Object> hashMap = new HashMap<>();
        hashMap.put(Constants.KEY_SHA256, newHash);
        source.put(Constants.KEY_HASH, hashMap);
        source.put(Constants.KEY_DOCUMENT, document);

        client
                .index(
                        new IndexRequest(Constants.INDEX_INTEGRATIONS)
                                .id(id)
                                .source(source)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }

    /**
     * Extracts a list of strings from a JSON node.
     *
     * @param parentNode The parent JSON node containing the list.
     * @param key The key of the list field.
     * @return A List of strings extracted from the JSON array.
     * @throws IllegalArgumentException If the field exists but is not an array.
     */
    public static List<String> extractStringList(JsonNode parentNode, String key) {
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

    /**
     * Validates that two lists contain the same set of elements, ignoring order. Used to ensure that
     * referenced resources (like rules or decoders) are not added or removed during specific updates.
     *
     * @param existingList The original list of strings.
     * @param incomingList The new list of strings.
     * @param fieldName The name of the field for error reporting.
     * @return A RestResponse error if the sets differ, or null if they are equal.
     */
    public static RestResponse validateListEquality(
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
}
