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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/** Service for retrieving resource information based on their Space. */
public class SpaceService {
    private static final Logger log = LogManager.getLogger(SpaceService.class);

    private final Client client;
    private final ObjectMapper objectMapper;
    private final PluginSettings pluginSettings;

    public SpaceService(Client client) {
        this.client = client;
        this.objectMapper = new ObjectMapper();
        this.pluginSettings = PluginSettings.getInstance();
    }

    /**
     * Fetches all resources (document.id and Hash) for a given space. Iterates over all managed
     * resource types and their corresponding indices.
     *
     * @param spaceName The space to filter by (e.g., "draft", "test")
     * @return A map where Key=ResourceType (e.g. "decoders") and Value=Map(document.id -> Hash)
     */
    public Map<String, Map<String, String>> getSpaceResources(String spaceName) {
        Map<String, Map<String, String>> spaceResources = new HashMap<>();

        for (Map.Entry<String, String> entry : Constants.RESOURCE_INDICES.entrySet()) {
            String resourceType = entry.getKey();
            String indexName = entry.getValue();

            Map<String, String> items = new HashMap<>();

            try {
                // Check if index exists before querying
                if (this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                    SearchRequest searchRequest = new SearchRequest(indexName);
                    SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();

                    // Filter by space and fetch document.id
                    sourceBuilder.query(QueryBuilders.termQuery("space.name", spaceName));
                    sourceBuilder.fetchSource(new String[] {"hash.sha256", "document.id"}, null);
                    sourceBuilder.size(10000);

                    searchRequest.source(sourceBuilder);
                    SearchResponse response = this.client.search(searchRequest).actionGet();

                    for (SearchHit hit : response.getHits().getHits()) {
                        String hash = HashCalculator.extractHash(hit.getSourceAsMap());
                        String docId = this.getDocumentId(hit.getSourceAsMap());
                        if (docId != null) {
                            items.put(docId, hash);
                        }
                    }
                } else {
                    throw new IndexNotFoundException("Index [" + indexName + "] not found.");
                }
            } catch (Exception e) {
                log.warn(
                        "Failed to fetch [{}] from index [{}] for space [{}]: {}",
                        resourceType,
                        indexName,
                        spaceName,
                        e.getMessage());
            }

            spaceResources.put(resourceType, items);
        }

        return spaceResources;
    }

    /**
     * Consolidates resources after validation by applying ADD/UPDATE operations. This method copies
     * documents from source space to target space and updates the space field.
     *
     * @param indexName The index to update.
     * @param resourcesToConsolidate Map of resource ID (document.id) to resource document (from
     *     source space).
     * @param targetSpace The target space name.
     * @throws IOException If the bulk update operation fails.
     */
    public void promoteSpace(
            String indexName, Map<String, Map<String, Object>> resourcesToConsolidate, String targetSpace)
            throws IOException {
        try {
            BulkRequest bulkRequest = new BulkRequest();

            for (Map.Entry<String, Map<String, Object>> entry : resourcesToConsolidate.entrySet()) {
                String docId = entry.getKey();
                Map<String, Object> doc = entry.getValue();

                // Update the space field to target space
                @SuppressWarnings("unchecked")
                Map<String, String> spaceMap =
                        (Map<String, String>) doc.getOrDefault("space", new HashMap<>());
                spaceMap.put("name", targetSpace);
                doc.put("space", spaceMap);

                // Find existing _id in target space to overwrite it, otherwise create new
                String targetId = this.findDocumentId(indexName, targetSpace, docId);

                IndexRequest indexRequest = new IndexRequest(indexName);
                if (targetId != null) {
                    indexRequest.id(targetId);
                }

                indexRequest.source(this.objectMapper.writeValueAsString(doc), XContentType.JSON);
                bulkRequest.add(indexRequest);
            }

            if (bulkRequest.numberOfActions() > 0) {
                BulkResponse response =
                        this.client
                                .bulk(bulkRequest)
                                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
                if (response.hasFailures()) {
                    throw new IOException("Bulk consolidation failed: " + response.buildFailureMessage());
                }
            }
        } catch (Exception e) {
            log.error("Failed to consolidate resources: {}", e.getMessage());
            throw new IOException("Failed to consolidate resources: " + e.getMessage(), e);
        }
    }

    /**
     * Fetches all documents from a specific index that belong to a given space, keyed by document.id.
     *
     * @param indexName The index to search.
     * @param spaceName The space to filter by.
     * @return A map of document.id to document content.
     * @throws IOException If the search operation fails.
     */
    public Map<String, Map<String, Object>> getResourcesBySpace(String indexName, String spaceName)
            throws IOException {
        Map<String, Map<String, Object>> resources = new HashMap<>();

        try {
            if (this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                SearchRequest searchRequest = new SearchRequest(indexName);
                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                sourceBuilder.query(QueryBuilders.termQuery("space.name", spaceName));
                sourceBuilder.size(10000);
                searchRequest.source(sourceBuilder);

                SearchResponse response = this.client.search(searchRequest).actionGet();

                for (SearchHit hit : response.getHits().getHits()) {
                    String docId = this.getDocumentId(hit.getSourceAsMap());
                    if (docId != null) {
                        resources.put(docId, hit.getSourceAsMap());
                    }
                }
            }
        } catch (Exception e) {
            log.error(
                    "Failed to fetch resources from [{}] for space [{}]: {}",
                    indexName,
                    spaceName,
                    e.getMessage());
            throw new IOException("Failed to fetch resources: " + e.getMessage(), e);
        }

        return resources;
    }

    /**
     * Builds the engine payload for validation by gathering all required resources. This method
     * starts with all resources from the target space and applies the modifications from the source
     * space according to the provided resource maps.
     *
     * @param policyDocument The base policy document from target space.
     * @param targetSpace The target space name.
     * @param integrationsToApply Map of integration IDs to their documents (from source space).
     * @param kvdbsToApply Map of kvdb IDs to their documents (from source space).
     * @param decodersToApply Map of decoder IDs to their documents (from source space).
     * @param filtersToApply Map of filter IDs to their documents (from source space).
     * @param integrationsToDelete Set of integration IDs to exclude.
     * @param kvdbsToDelete Set of kvdb IDs to exclude.
     * @param decodersToDelete Set of decoder IDs to exclude.
     * @param filtersToDelete Set of filter IDs to exclude.
     * @return A JsonNode representing the engine payload.
     * @throws IOException If any document retrieval fails.
     */
    public JsonNode buildEnginePayload(
            Map<String, Object> policyDocument,
            String targetSpace,
            Map<String, Map<String, Object>> integrationsToApply,
            Map<String, Map<String, Object>> kvdbsToApply,
            Map<String, Map<String, Object>> decodersToApply,
            Map<String, Map<String, Object>> filtersToApply,
            java.util.Set<String> integrationsToDelete,
            java.util.Set<String> kvdbsToDelete,
            java.util.Set<String> decodersToDelete,
            java.util.Set<String> filtersToDelete)
            throws IOException {

        // Root payload structure
        ObjectNode rootPayload = this.objectMapper.createObjectNode();
        rootPayload.put("load_in_tester", true);

        // Create the full_policy object
        ObjectNode fullPolicyNode = this.objectMapper.createObjectNode();

        // Build the policy object
        ObjectNode policyNode = this.objectMapper.createObjectNode();
        if (policyDocument != null && policyDocument.containsKey(Constants.KEY_DOCUMENT)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> policyDoc =
                    (Map<String, Object>) policyDocument.get(Constants.KEY_DOCUMENT);
            JsonNode policyContentNode = this.objectMapper.valueToTree(policyDoc);
            policyNode.setAll((ObjectNode) policyContentNode);
        }
        fullPolicyNode.set("policy", policyNode);

        // Build the resources object
        ObjectNode resourcesNode = this.objectMapper.createObjectNode();

        // Fetch all integrations from target space
        Map<String, Map<String, Object>> targetIntegrations =
                this.getResourcesBySpace(Constants.INDEX_INTEGRATIONS, targetSpace);
        // Apply modifications
        targetIntegrations.putAll(integrationsToApply);
        // Remove deletions
        for (String id : integrationsToDelete) {
            targetIntegrations.remove(id);
        }
        // Build array
        ArrayNode integrationsArray = this.buildResourceArray(targetIntegrations);
        resourcesNode.set(Constants.KEY_INTEGRATIONS, integrationsArray);

        // Fetch all kvdbs from target space
        Map<String, Map<String, Object>> targetKvdbs =
                this.getResourcesBySpace(Constants.INDEX_KVDBS, targetSpace);
        targetKvdbs.putAll(kvdbsToApply);
        for (String id : kvdbsToDelete) {
            targetKvdbs.remove(id);
        }
        ArrayNode kvdbsArray = this.buildResourceArray(targetKvdbs);
        resourcesNode.set(Constants.KEY_KVDBS, kvdbsArray);

        // Fetch all decoders from target space
        Map<String, Map<String, Object>> targetDecoders =
                this.getResourcesBySpace(Constants.INDEX_DECODERS, targetSpace);
        targetDecoders.putAll(decodersToApply);
        for (String id : decodersToDelete) {
            targetDecoders.remove(id);
        }
        ArrayNode decodersArray = this.buildResourceArray(targetDecoders);
        resourcesNode.set(Constants.KEY_DECODERS, decodersArray);

        // Fetch all filters from target space
        Map<String, Map<String, Object>> targetFilters =
                this.getResourcesBySpace(Constants.INDEX_FILTERS, targetSpace);
        targetFilters.putAll(filtersToApply);
        for (String id : filtersToDelete) {
            targetFilters.remove(id);
        }
        ArrayNode filtersArray = this.buildResourceArray(targetFilters);
        resourcesNode.set(Constants.KEY_FILTERS, filtersArray);

        // Add resources to full_policy
        fullPolicyNode.set("resources", resourcesNode);

        // Add full_policy to root
        rootPayload.set("full_policy", fullPolicyNode);

        return rootPayload;
    }

    /**
     * Helper method to build a JSON array from a map of resources.
     *
     * @param resources Map of resource ID to resource document.
     * @return An ArrayNode containing the document content of each resource.
     */
    private ArrayNode buildResourceArray(Map<String, Map<String, Object>> resources) {
        ArrayNode array = this.objectMapper.createArrayNode();
        for (Map<String, Object> resource : resources.values()) {
            if (resource.containsKey(Constants.KEY_DOCUMENT)) {
                @SuppressWarnings("unchecked")
                Map<String, Object> content = (Map<String, Object>) resource.get(Constants.KEY_DOCUMENT);
                JsonNode node = this.objectMapper.valueToTree(content);
                array.add(node);
            }
        }
        return array;
    }

    /**
     * Gets the index name for a given resource type.
     *
     * @param resourceType The resource type key (e.g., "decoders", "kvdbs").
     * @return The index name, or null if not found.
     */
    public String getIndexForResourceType(String resourceType) {
        return Constants.RESOURCE_INDICES.get(resourceType);
    }

    /**
     * Retrieves a document from the specified index by ID.
     *
     * @param indexName The name of the index to search.
     * @param id The document ID.
     * @return The document as a Map, or null if not found.
     * @throws IOException If the retrieval operation fails.
     */
    public Map<String, Object> getDocument(String indexName, String id) throws IOException {
        try {
            GetRequest request = new GetRequest(indexName, id);
            GetResponse response =
                    this.client.get(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

            if (response.isExists()) {
                return response.getSourceAsMap();
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to get document [{}] from index [{}]: {}", id, indexName, e.getMessage());
            throw new IOException("Failed to retrieve document: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves a document from the specified index by its logical ID (document.id) within a space.
     *
     * @param indexName The name of the index to search.
     * @param space The space name.
     * @param documentId The logical document ID.
     * @return The document as a Map, or null if not found.
     * @throws IOException If the retrieval operation fails.
     */
    public Map<String, Object> getDocument(String indexName, String space, String documentId)
            throws IOException {
        String realId = this.findDocumentId(indexName, space, documentId);
        if (realId != null) {
            return this.getDocument(indexName, realId);
        }
        return null;
    }

    /**
     * Fetches the full policy document from the policies index by searching for the space.
     *
     * @param space The space of the policy document.
     * @return The policy document as a Map, or null if not found.
     * @throws IOException If the retrieval operation fails.
     */
    public Map<String, Object> getPolicy(String space) throws IOException {
        try {
            SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
            sourceBuilder.query(QueryBuilders.termQuery("space.name", space));
            sourceBuilder.size(1);
            searchRequest.source(sourceBuilder);

            SearchResponse response = this.client.search(searchRequest).actionGet();

            if (response.getHits().getTotalHits().value() > 0) {
                SearchHit hit = response.getHits().getAt(0);
                return hit.getSourceAsMap();
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to get policy for space [{}]: {}", space, e.getMessage());
            throw new IOException("Failed to retrieve policy: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes resources from the target space after validation.
     *
     * @param indexName The index to delete from.
     * @param resourceIdsToDelete Set of resource IDs (document.id) to delete.
     * @param targetSpace The target space (for verification).
     * @throws IOException If the delete operation fails.
     */
    public void deleteResources(
            String indexName, java.util.Set<String> resourceIdsToDelete, String targetSpace)
            throws IOException {
        try {
            BulkRequest bulkRequest = new BulkRequest();

            for (String docId : resourceIdsToDelete) {
                // Find the document in the target space using the logical ID
                String targetId = this.findDocumentId(indexName, targetSpace, docId);

                if (targetId != null) {
                    DeleteRequest deleteRequest = new DeleteRequest(indexName, targetId);
                    bulkRequest.add(deleteRequest);
                } else {
                    log.warn(
                            "Document with document.id [{}] not found in space [{}] for deletion",
                            docId,
                            targetSpace);
                }
            }

            if (bulkRequest.numberOfActions() > 0) {
                BulkResponse response =
                        this.client
                                .bulk(bulkRequest)
                                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
                if (response.hasFailures()) {
                    throw new IOException("Bulk deletion failed: " + response.buildFailureMessage());
                }
            }
        } catch (Exception e) {
            log.error("Failed to delete resources: {}", e.getMessage());
            throw new IOException("Failed to delete resources: " + e.getMessage(), e);
        }
    }

    /**
     * Extract document.id from a source document
     *
     * @param source Document object that contains the field ID
     * @return ID of the document in string format
     */
    @SuppressWarnings("unchecked")
    private String getDocumentId(Map<String, Object> source) {
        if (source != null && source.containsKey(Constants.KEY_DOCUMENT)) {
            Map<String, Object> doc = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
            return (String) doc.get("id");
        }
        return null;
    }

    /**
     * Finds the real _id of a document given its logical document.id and space.
     *
     * @param indexName The index to search.
     * @param spaceName The space name.
     * @param documentId The logical document ID.
     * @return The real _id, or null if not found.
     */
    private String findDocumentId(String indexName, String spaceName, String documentId) {
        try {
            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
            sourceBuilder.query(
                    QueryBuilders.boolQuery()
                            .must(QueryBuilders.termQuery("space.name", spaceName))
                            .must(QueryBuilders.termQuery("document.id", documentId)));
            sourceBuilder.size(1);
            sourceBuilder.fetchSource(false); // We only need the _id
            searchRequest.source(sourceBuilder);

            SearchResponse response = this.client.search(searchRequest).actionGet();
            if (response.getHits().getTotalHits().value() > 0) {
                return response.getHits().getAt(0).getId();
            }
        } catch (Exception e) {
            log.error(
                    "Error finding document ID for space [{}] and docId [{}]: {}",
                    spaceName,
                    documentId,
                    e.getMessage());
        }
        return null;
    }
}
