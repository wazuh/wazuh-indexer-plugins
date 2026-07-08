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
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
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
     * Executes a blocking task on the generic thread pool so that it does not block a transport
     * thread. This avoids {@code AssertionError: Expected current thread to not be a transport
     * thread} errors when {@code actionGet()} is called from a REST handler context.
     *
     * @param <T> the return type
     * @param task the callable to execute
     * @return the result of the callable
     * @throws IOException if execution fails
     */
    private <T> T offloadBlocking(Callable<T> task) throws IOException {
        try {
            return this.client.threadPool().generic().submit(task).get();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            throw new IOException("Blocking execution failed", cause);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for search result", e);
        }
    }

    /**
     * Deletes all documents related to a specific space across all resource indices.
     *
     * @param space The name of the space to wipe.
     * @throws IOException If the deletion process fails.
     */
    public void deleteSpaceResources(Space space) throws IOException {
        String spaceName = space.toString();
        try {
            BulkRequest bulkRequest = new BulkRequest();

            for (String indexName : Constants.RESOURCE_INDICES.values()) {
                boolean exists =
                        this.offloadBlocking(
                                () -> this.client.admin().indices().prepareExists(indexName).get().isExists());
                if (exists) {
                    SearchRequest searchRequest = new SearchRequest(indexName);
                    SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                    sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName));
                    sourceBuilder.size(10000);
                    sourceBuilder.fetchSource(false); // We only need the _id
                    searchRequest.source(sourceBuilder);

                    SearchResponse response =
                            this.offloadBlocking(() -> this.client.search(searchRequest).actionGet());

                    for (SearchHit hit : response.getHits().getHits()) {
                        bulkRequest.add(new DeleteRequest(indexName, hit.getId()));
                    }
                }
            }

            if (bulkRequest.numberOfActions() > 0) {
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                BulkResponse response =
                        this.offloadBlocking(() -> this.client.bulk(bulkRequest).actionGet());
                if (response.hasFailures()) {
                    throw new IOException("Bulk deletion failed: " + response.buildFailureMessage());
                }
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_DELETE_SPACE_RESOURCES_FAILED, spaceName, e.getMessage());
            throw new IOException("Failed to delete space resources: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a single space policy document if it does not already exist.
     *
     * <p>Uses a deterministic, space-specific OpenSearch document ID so that {@link
     * DocWriteRequest.OpType#CREATE} acts as an atomic guard: if two nodes race on startup, the
     * second write raises a {@link VersionConflictEngineException} which is silently ignored.
     *
     * @param spaceName The space name.
     * @param documentId Shared policy ID stored inside the document to link all default spaces.
     */
    public void initializeSpace(String spaceName, String documentId) {
        // Deterministic, space-specific OpenSearch _id.
        // Combined with OpType.CREATE this guarantees exactly-once creation per space,
        // even when multiple nodes call this method concurrently.
        String spaceDocId =
                UUID.nameUUIDFromBytes(("wazuh-space-" + spaceName).getBytes(StandardCharsets.UTF_8))
                        .toString();
        try {
            String date = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
            String title = "Custom space";

            Policy policy = new Policy();
            policy.setId(documentId);
            policy.setTitle(title);
            policy.setDescription(title);
            policy.setAuthor("Custom");
            policy.setRootDecoder(null);
            policy.setDocumentation("");
            policy.setIntegrations(Collections.emptyList());
            policy.setFilters(Collections.emptyList());
            policy.setEnrichments(Collections.emptyList());
            policy.setReferences(Collections.emptyList());
            policy.setDate(date);
            policy.setModified(date);
            // Enable the policy by default for the draft space only
            policy.setEnabled(Space.DRAFT.toString().equals(spaceName));
            policy.setIndexUnclassifiedEvents(false);
            policy.setIndexDiscardedEvents(false);

            ObjectNode docNode = this.objectMapper.valueToTree(policy);
            Resource.nestMetadataFields(docNode);
            @SuppressWarnings("unchecked")
            Map<String, Object> docMap = this.objectMapper.convertValue(docNode, Map.class);

            String docJson = this.objectMapper.writeValueAsString(docMap);
            String docHash = Resource.computeSha256(docJson);

            Map<String, Object> space = new HashMap<>();
            space.put(Constants.KEY_NAME, spaceName);
            space.put(Constants.KEY_HASH, Map.of(Constants.KEY_SHA256, docHash));

            Map<String, Object> source = new HashMap<>();
            source.put(Constants.KEY_DOCUMENT, docMap);
            source.put(Constants.KEY_SPACE, space);
            source.put(Constants.KEY_HASH, Map.of(Constants.KEY_SHA256, docHash));

            IndexRequest request =
                    new IndexRequest(Constants.INDEX_POLICIES)
                            .id(spaceDocId)
                            .source(this.objectMapper.writeValueAsString(source), XContentType.JSON)
                            .opType(DocWriteRequest.OpType.CREATE)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

            this.client.index(request).actionGet();
            log.info(Constants.I_LOG_SPACE_INITIALIZED, spaceName);
        } catch (VersionConflictEngineException e) {
            log.debug(Constants.D_LOG_SPACE_ALREADY_INITIALIZED, spaceName);
        } catch (Exception e) {
            log.error(Constants.E_LOG_INITIALIZE_SPACE_FAILED, spaceName, e.getMessage());
        }
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
                    sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName));
                    sourceBuilder.fetchSource(new String[] {Constants.Q_HASH, Constants.Q_DOCUMENT_ID}, null);
                    sourceBuilder.size(10000);

                    searchRequest.source(sourceBuilder);
                    SearchResponse response =
                            this.offloadBlocking(() -> this.client.search(searchRequest).actionGet());

                    for (SearchHit hit : response.getHits().getHits()) {
                        String hash = Resource.extractHash(hit.getSourceAsMap());
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
                        Constants.W_LOG_FETCH_RESOURCE_TYPE_FAILED,
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
     * Asynchronously fetches all resources (document.id and Hash) for a given space.
     *
     * @param spaceName The space to filter by (e.g., "draft", "test")
     * @param listener receives a map where Key=ResourceType and Value=Map(document.id -> Hash)
     */
    public void getSpaceResourcesAsync(
            String spaceName, ActionListener<Map<String, Map<String, String>>> listener) {
        List<Map.Entry<String, String>> entries =
                new ArrayList<>(Constants.RESOURCE_INDICES.entrySet());
        fetchResourceTypeAsync(spaceName, entries, 0, new HashMap<>(), listener);
    }

    private void fetchResourceTypeAsync(
            String spaceName,
            List<Map.Entry<String, String>> entries,
            int idx,
            Map<String, Map<String, String>> accumulator,
            ActionListener<Map<String, Map<String, String>>> listener) {
        if (idx >= entries.size()) {
            listener.onResponse(accumulator);
            return;
        }

        String resourceType = entries.get(idx).getKey();
        String indexName = entries.get(idx).getValue();

        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(indexName),
                        ActionListener.wrap(
                                existsResponse -> {
                                    if (!existsResponse.isExists()) {
                                        log.warn(
                                                Constants.W_LOG_FETCH_RESOURCE_TYPE_FAILED,
                                                resourceType,
                                                indexName,
                                                spaceName,
                                                "Index [" + indexName + "] not found.");
                                        accumulator.put(resourceType, new HashMap<>());
                                        fetchResourceTypeAsync(spaceName, entries, idx + 1, accumulator, listener);
                                        return;
                                    }
                                    searchResourceTypeAsync(
                                            spaceName, resourceType, indexName, entries, idx, accumulator, listener);
                                },
                                e -> {
                                    log.warn(
                                            Constants.W_LOG_FETCH_RESOURCE_TYPE_FAILED,
                                            resourceType,
                                            indexName,
                                            spaceName,
                                            e.getMessage());
                                    accumulator.put(resourceType, new HashMap<>());
                                    fetchResourceTypeAsync(spaceName, entries, idx + 1, accumulator, listener);
                                }));
    }

    private void searchResourceTypeAsync(
            String spaceName,
            String resourceType,
            String indexName,
            List<Map.Entry<String, String>> entries,
            int idx,
            Map<String, Map<String, String>> accumulator,
            ActionListener<Map<String, Map<String, String>>> listener) {
        SearchRequest searchRequest = new SearchRequest(indexName);
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName));
        sourceBuilder.fetchSource(new String[] {Constants.Q_HASH, Constants.Q_DOCUMENT_ID}, null);
        sourceBuilder.size(10000);
        searchRequest.source(sourceBuilder);

        this.client.search(
                searchRequest,
                ActionListener.wrap(
                        response -> {
                            Map<String, String> items = new HashMap<>();
                            for (SearchHit hit : response.getHits().getHits()) {
                                String hash = Resource.extractHash(hit.getSourceAsMap());
                                String docId = this.getDocumentId(hit.getSourceAsMap());
                                if (docId != null) {
                                    items.put(docId, hash);
                                }
                            }
                            accumulator.put(resourceType, items);
                            fetchResourceTypeAsync(spaceName, entries, idx + 1, accumulator, listener);
                        },
                        e -> {
                            log.warn(
                                    Constants.W_LOG_FETCH_RESOURCE_TYPE_FAILED,
                                    resourceType,
                                    indexName,
                                    spaceName,
                                    e.getMessage());
                            accumulator.put(resourceType, new HashMap<>());
                            fetchResourceTypeAsync(spaceName, entries, idx + 1, accumulator, listener);
                        }));
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
                        (Map<String, String>) doc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                spaceMap.put(Constants.KEY_NAME, targetSpace);
                doc.put(Constants.KEY_SPACE, spaceMap);

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
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                BulkResponse response =
                        this.client
                                .bulk(bulkRequest)
                                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
                if (response.hasFailures()) {
                    throw new IOException("Bulk consolidation failed: " + response.buildFailureMessage());
                }
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_CONSOLIDATE_RESOURCES_FAILED, e.getMessage());
            throw new IOException("Failed to consolidate resources: " + e.getMessage(), e);
        }
    }

    /**
     * Fetches all documents from a specific index that belong to a given space, keyed by document.id.
     *
     * @param indexName The index to search.
     * @param space The space to filter by.
     * @return A map of document.id to document content.
     * @throws IOException If the search operation fails.
     */
    public Map<String, Map<String, Object>> getResourcesBySpace(String indexName, Space space)
            throws IOException {
        Map<String, Map<String, Object>> resources = new HashMap<>();

        try {
            if (this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                SearchRequest searchRequest = new SearchRequest(indexName);
                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()));
                sourceBuilder.size(10000);
                searchRequest.source(sourceBuilder);

                SearchResponse response =
                        this.offloadBlocking(() -> this.client.search(searchRequest).actionGet());

                for (SearchHit hit : response.getHits().getHits()) {
                    String docId = this.getDocumentId(hit.getSourceAsMap());
                    if (docId != null) {
                        resources.put(docId, hit.getSourceAsMap());
                    }
                }
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_FETCH_RESOURCES_FAILED, indexName, space, e.getMessage());
            throw new IOException("Failed to fetch resources: " + e.getMessage(), e);
        }

        return resources;
    }

    /**
     * Asynchronously fetches all documents from a specific index that belong to a given space.
     *
     * @param indexName The index to search.
     * @param space The space to filter by.
     * @param listener receives a map of document.id to document content.
     */
    public void getResourcesBySpaceAsync(
            String indexName, Space space, ActionListener<Map<String, Map<String, Object>>> listener) {
        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(indexName),
                        ActionListener.wrap(
                                existsResponse -> {
                                    if (!existsResponse.isExists()) {
                                        listener.onResponse(new HashMap<>());
                                        return;
                                    }
                                    SearchRequest searchRequest = new SearchRequest(indexName);
                                    SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                                    sourceBuilder.query(
                                            QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()));
                                    sourceBuilder.size(10000);
                                    searchRequest.source(sourceBuilder);

                                    this.client.search(
                                            searchRequest,
                                            ActionListener.wrap(
                                                    response -> {
                                                        Map<String, Map<String, Object>> resources = new HashMap<>();
                                                        for (SearchHit hit : response.getHits().getHits()) {
                                                            String docId = this.getDocumentId(hit.getSourceAsMap());
                                                            if (docId != null) {
                                                                resources.put(docId, hit.getSourceAsMap());
                                                            }
                                                        }
                                                        listener.onResponse(resources);
                                                    },
                                                    e -> {
                                                        log.error(
                                                                Constants.E_LOG_FETCH_RESOURCES_FAILED,
                                                                indexName,
                                                                space,
                                                                e.getMessage());
                                                        listener.onFailure(
                                                                new IOException("Failed to fetch resources: " + e.getMessage(), e));
                                                    }));
                                },
                                e -> {
                                    log.error(
                                            Constants.E_LOG_FETCH_RESOURCES_FAILED, indexName, space, e.getMessage());
                                    listener.onFailure(
                                            new IOException("Failed to fetch resources: " + e.getMessage(), e));
                                }));
    }

    /**
     * Fetches only the document IDs from a specific index that belong to a given space.
     *
     * <p>Use this instead of {@link #getResourcesBySpace} when full document content is not needed,
     * to avoid loading large source maps into heap.
     *
     * @param indexName The index to search.
     * @param space The space to filter by.
     * @return A set of document.id values.
     * @throws IOException If the search operation fails.
     */
    public Set<String> getResourceIdsBySpace(String indexName, Space space) throws IOException {
        Set<String> ids = new HashSet<>();

        try {
            if (this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                SearchRequest searchRequest = new SearchRequest(indexName);
                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()));
                sourceBuilder.size(10000);
                sourceBuilder.fetchSource(new String[] {Constants.Q_DOCUMENT_ID}, null);
                searchRequest.source(sourceBuilder);

                SearchResponse response =
                        this.offloadBlocking(() -> this.client.search(searchRequest).actionGet());

                for (SearchHit hit : response.getHits().getHits()) {
                    String docId = this.getDocumentId(hit.getSourceAsMap());
                    if (docId != null) {
                        ids.add(docId);
                    }
                }
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_FETCH_RESOURCES_FAILED, indexName, space, e.getMessage());
            throw new IOException("Failed to fetch resource IDs: " + e.getMessage(), e);
        }

        return ids;
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
            Set<String> integrationsToDelete,
            Set<String> kvdbsToDelete,
            Set<String> decodersToDelete,
            Set<String> filtersToDelete)
            throws IOException {

        Space space = Space.fromValue(targetSpace);

        Map<String, Map<String, Object>> targetIntegrations =
                this.getResourcesBySpace(Constants.INDEX_INTEGRATIONS, space);
        targetIntegrations.putAll(integrationsToApply);
        integrationsToDelete.forEach(targetIntegrations::remove);

        Map<String, Map<String, Object>> targetKvdbs =
                this.getResourcesBySpace(Constants.INDEX_KVDBS, space);
        targetKvdbs.putAll(kvdbsToApply);
        kvdbsToDelete.forEach(targetKvdbs::remove);

        Map<String, Map<String, Object>> targetDecoders =
                this.getResourcesBySpace(Constants.INDEX_DECODERS, space);
        targetDecoders.putAll(decodersToApply);
        decodersToDelete.forEach(targetDecoders::remove);

        Map<String, Map<String, Object>> targetFilters =
                this.getResourcesBySpace(Constants.INDEX_FILTERS, space);
        targetFilters.putAll(filtersToApply);
        filtersToDelete.forEach(targetFilters::remove);

        return assembleEnginePayload(
                policyDocument,
                targetSpace,
                targetIntegrations,
                targetKvdbs,
                targetDecoders,
                targetFilters);
    }

    /**
     * Asynchronously builds the engine payload for validation by gathering all required resources.
     *
     * @param policyDocument The base policy document from the source space.
     * @param targetSpace The target space name.
     * @param integrationsToApply Map of integration IDs to their documents.
     * @param kvdbsToApply Map of kvdb IDs to their documents.
     * @param decodersToApply Map of decoder IDs to their documents.
     * @param filtersToApply Map of filter IDs to their documents.
     * @param integrationsToDelete Set of integration IDs to exclude.
     * @param kvdbsToDelete Set of kvdb IDs to exclude.
     * @param decodersToDelete Set of decoder IDs to exclude.
     * @param filtersToDelete Set of filter IDs to exclude.
     * @param listener receives the assembled engine payload.
     */
    public void buildEnginePayloadAsync(
            Map<String, Object> policyDocument,
            String targetSpace,
            Map<String, Map<String, Object>> integrationsToApply,
            Map<String, Map<String, Object>> kvdbsToApply,
            Map<String, Map<String, Object>> decodersToApply,
            Map<String, Map<String, Object>> filtersToApply,
            Set<String> integrationsToDelete,
            Set<String> kvdbsToDelete,
            Set<String> decodersToDelete,
            Set<String> filtersToDelete,
            ActionListener<JsonNode> listener) {

        Space space = Space.fromValue(targetSpace);

        List<String> indices =
                List.of(
                        Constants.INDEX_INTEGRATIONS,
                        Constants.INDEX_KVDBS,
                        Constants.INDEX_DECODERS,
                        Constants.INDEX_FILTERS);
        List<Map<String, Map<String, Object>>> applyMaps =
                List.of(integrationsToApply, kvdbsToApply, decodersToApply, filtersToApply);
        List<Set<String>> deleteSets =
                List.of(integrationsToDelete, kvdbsToDelete, decodersToDelete, filtersToDelete);

        List<Map<String, Map<String, Object>>> fetched = new ArrayList<>();
        fetchEngineResourcesAsync(
                space,
                indices,
                applyMaps,
                deleteSets,
                0,
                fetched,
                ActionListener.wrap(
                        v ->
                                listener.onResponse(
                                        assembleEnginePayload(
                                                policyDocument,
                                                targetSpace,
                                                fetched.get(0),
                                                fetched.get(1),
                                                fetched.get(2),
                                                fetched.get(3))),
                        listener::onFailure));
    }

    private void fetchEngineResourcesAsync(
            Space space,
            List<String> indices,
            List<Map<String, Map<String, Object>>> applyMaps,
            List<Set<String>> deleteSets,
            int idx,
            List<Map<String, Map<String, Object>>> fetched,
            ActionListener<Void> listener) {
        if (idx >= indices.size()) {
            listener.onResponse(null);
            return;
        }
        getResourcesBySpaceAsync(
                indices.get(idx),
                space,
                ActionListener.wrap(
                        (Map<String, Map<String, Object>> resources) -> {
                            resources.putAll(applyMaps.get(idx));
                            deleteSets.get(idx).forEach(resources::remove);
                            fetched.add(resources);
                            fetchEngineResourcesAsync(
                                    space, indices, applyMaps, deleteSets, idx + 1, fetched, listener);
                        },
                        listener::onFailure));
    }

    private JsonNode assembleEnginePayload(
            Map<String, Object> policyDocument,
            String targetSpace,
            Map<String, Map<String, Object>> targetIntegrations,
            Map<String, Map<String, Object>> targetKvdbs,
            Map<String, Map<String, Object>> targetDecoders,
            Map<String, Map<String, Object>> targetFilters) {

        ObjectNode rootPayload = this.objectMapper.createObjectNode();
        boolean isTesterSpace = !Space.DRAFT.toString().equals(targetSpace);
        rootPayload.put(Constants.KEY_PROMOTE, isTesterSpace);
        rootPayload.put(Constants.KEY_SPACE, targetSpace);

        ObjectNode fullPolicyNode = this.objectMapper.createObjectNode();

        ObjectNode policyNode = this.objectMapper.createObjectNode();
        if (policyDocument != null && policyDocument.containsKey(Constants.KEY_DOCUMENT)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> policyDoc =
                    (Map<String, Object>) policyDocument.get(Constants.KEY_DOCUMENT);
            JsonNode policyContentNode = this.objectMapper.valueToTree(policyDoc);
            policyNode.setAll((ObjectNode) policyContentNode);
        }
        fullPolicyNode.set(Constants.KEY_POLICY, policyNode);

        ObjectNode resourcesNode = this.objectMapper.createObjectNode();
        resourcesNode.set(Constants.KEY_INTEGRATIONS, this.buildResourceArray(targetIntegrations));
        resourcesNode.set(Constants.KEY_KVDBS, this.buildResourceArray(targetKvdbs));
        resourcesNode.set(Constants.KEY_DECODERS, this.buildResourceArray(targetDecoders));
        resourcesNode.set(Constants.KEY_FILTERS, this.buildResourceArray(targetFilters));
        fullPolicyNode.set(Constants.KEY_RESOURCES, resourcesNode);

        rootPayload.set(Constants.KEY_FULL_POLICY, fullPolicyNode);
        return rootPayload;
    }

    /**
     * Builds the engine payload for a full space without any modifications. This is used to load an
     * entire space into the Engine, such as the standard space after a CTI sync.
     *
     * @param spaceName The space name to build the payload for.
     * @return A JsonNode representing the engine payload.
     * @throws IOException If the policy or resource retrieval fails.
     */
    public JsonNode buildEnginePayload(String spaceName) throws IOException {
        Map<String, Object> policyDocument = this.getPolicy(spaceName);
        return this.buildEnginePayload(
                policyDocument,
                spaceName,
                Collections.emptyMap(),
                Collections.emptyMap(),
                Collections.emptyMap(),
                Collections.emptyMap(),
                Collections.emptySet(),
                Collections.emptySet(),
                Collections.emptySet(),
                Collections.emptySet());
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
            log.error(Constants.E_LOG_GET_DOCUMENT_FAILED, id, indexName, e.getMessage());
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
     * Asynchronously retrieves a document from the specified index by ID.
     *
     * @param indexName The name of the index to search.
     * @param id The document ID.
     * @param listener receives the document as a Map, or null if not found.
     */
    public void getDocumentAsync(
            String indexName, String id, ActionListener<Map<String, Object>> listener) {
        this.client.get(
                new GetRequest(indexName, id),
                ActionListener.wrap(
                        response -> listener.onResponse(response.isExists() ? response.getSourceAsMap() : null),
                        e -> {
                            log.error(Constants.E_LOG_GET_DOCUMENT_FAILED, id, indexName, e.getMessage());
                            listener.onFailure(
                                    new IOException("Failed to retrieve document: " + e.getMessage(), e));
                        }));
    }

    /**
     * Asynchronously retrieves a document by its logical ID (document.id) within a space.
     *
     * @param indexName The name of the index to search.
     * @param space The space name.
     * @param documentId The logical document ID.
     * @param listener receives the document as a Map, or null if not found.
     */
    public void getDocumentAsync(
            String indexName,
            String space,
            String documentId,
            ActionListener<Map<String, Object>> listener) {
        findDocumentIdAsync(
                indexName,
                space,
                documentId,
                ActionListener.wrap(
                        realId -> {
                            if (realId != null) {
                                getDocumentAsync(indexName, realId, listener);
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        listener::onFailure));
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
            sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space));
            sourceBuilder.size(1);
            searchRequest.source(sourceBuilder);

            SearchResponse response =
                    this.offloadBlocking(() -> this.client.search(searchRequest).actionGet());

            if (response.getHits().getTotalHits().value() > 0) {
                SearchHit hit = response.getHits().getAt(0);
                return hit.getSourceAsMap();
            }
            return null;
        } catch (Exception e) {
            log.error(Constants.E_LOG_GET_POLICY_FAILED, space, e.getMessage());
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
    public void deleteResources(String indexName, Set<String> resourceIdsToDelete, String targetSpace)
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
                    log.warn(Constants.W_LOG_DOCUMENT_NOT_FOUND_FOR_DELETION, docId, targetSpace);
                }
            }

            if (bulkRequest.numberOfActions() > 0) {
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                BulkResponse response =
                        this.client
                                .bulk(bulkRequest)
                                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
                if (response.hasFailures()) {
                    throw new IOException("Bulk deletion failed: " + response.buildFailureMessage());
                }
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_DELETE_RESOURCES_FAILED, e.getMessage());
            throw new IOException("Failed to delete resources: " + e.getMessage(), e);
        }
    }

    /**
     * Asynchronously consolidates resources by applying ADD/UPDATE operations.
     *
     * @param indexName The index to update.
     * @param resourcesToConsolidate Map of resource ID (document.id) to resource document.
     * @param targetSpace The target space name.
     * @param listener notified on completion or failure.
     */
    public void promoteSpaceAsync(
            String indexName,
            Map<String, Map<String, Object>> resourcesToConsolidate,
            String targetSpace,
            ActionListener<Void> listener) {
        List<String> docIds = new ArrayList<>(resourcesToConsolidate.keySet());
        resolveDocumentIdsAsync(
                indexName,
                targetSpace,
                docIds,
                0,
                new HashMap<>(),
                ActionListener.wrap(
                        resolvedIds -> {
                            try {
                                BulkRequest bulkRequest = new BulkRequest();
                                for (Map.Entry<String, Map<String, Object>> entry :
                                        resourcesToConsolidate.entrySet()) {
                                    String docId = entry.getKey();
                                    Map<String, Object> doc = entry.getValue();

                                    @SuppressWarnings("unchecked")
                                    Map<String, String> spaceMap =
                                            (Map<String, String>) doc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                                    spaceMap.put(Constants.KEY_NAME, targetSpace);
                                    doc.put(Constants.KEY_SPACE, spaceMap);

                                    IndexRequest indexRequest = new IndexRequest(indexName);
                                    String targetId = resolvedIds.get(docId);
                                    if (targetId != null) {
                                        indexRequest.id(targetId);
                                    }
                                    indexRequest.source(this.objectMapper.writeValueAsString(doc), XContentType.JSON);
                                    bulkRequest.add(indexRequest);
                                }
                                if (bulkRequest.numberOfActions() == 0) {
                                    listener.onResponse(null);
                                    return;
                                }
                                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                                this.client.bulk(
                                        bulkRequest,
                                        ActionListener.wrap(
                                                response -> {
                                                    if (response.hasFailures()) {
                                                        listener.onFailure(
                                                                new IOException(
                                                                        "Bulk consolidation failed: "
                                                                                + response.buildFailureMessage()));
                                                    } else {
                                                        listener.onResponse(null);
                                                    }
                                                },
                                                listener::onFailure));
                            } catch (Exception e) {
                                log.error(Constants.E_LOG_CONSOLIDATE_RESOURCES_FAILED, e.getMessage());
                                listener.onFailure(
                                        new IOException("Failed to consolidate resources: " + e.getMessage(), e));
                            }
                        },
                        listener::onFailure));
    }

    /**
     * Asynchronously deletes resources from the target space.
     *
     * @param indexName The index to delete from.
     * @param resourceIdsToDelete Set of resource IDs (document.id) to delete.
     * @param targetSpace The target space (for verification).
     * @param listener notified on completion or failure.
     */
    public void deleteResourcesAsync(
            String indexName,
            Set<String> resourceIdsToDelete,
            String targetSpace,
            ActionListener<Void> listener) {
        List<String> docIds = new ArrayList<>(resourceIdsToDelete);
        resolveDocumentIdsAsync(
                indexName,
                targetSpace,
                docIds,
                0,
                new HashMap<>(),
                ActionListener.wrap(
                        resolvedIds -> {
                            BulkRequest bulkRequest = new BulkRequest();
                            for (String docId : resourceIdsToDelete) {
                                String targetId = resolvedIds.get(docId);
                                if (targetId != null) {
                                    bulkRequest.add(new DeleteRequest(indexName, targetId));
                                } else {
                                    log.warn(Constants.W_LOG_DOCUMENT_NOT_FOUND_FOR_DELETION, docId, targetSpace);
                                }
                            }
                            if (bulkRequest.numberOfActions() == 0) {
                                listener.onResponse(null);
                                return;
                            }
                            bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                            this.client.bulk(
                                    bulkRequest,
                                    ActionListener.wrap(
                                            response -> {
                                                if (response.hasFailures()) {
                                                    listener.onFailure(
                                                            new IOException(
                                                                    "Bulk deletion failed: " + response.buildFailureMessage()));
                                                } else {
                                                    listener.onResponse(null);
                                                }
                                            },
                                            listener::onFailure));
                        },
                        e -> {
                            log.error(Constants.E_LOG_DELETE_RESOURCES_FAILED, e.getMessage());
                            listener.onFailure(
                                    new IOException("Failed to delete resources: " + e.getMessage(), e));
                        }));
    }

    private void resolveDocumentIdsAsync(
            String indexName,
            String spaceName,
            List<String> docIds,
            int idx,
            Map<String, String> resolved,
            ActionListener<Map<String, String>> listener) {
        if (idx >= docIds.size()) {
            listener.onResponse(resolved);
            return;
        }
        findDocumentIdAsync(
                indexName,
                spaceName,
                docIds.get(idx),
                ActionListener.wrap(
                        realId -> {
                            if (realId != null) {
                                resolved.put(docIds.get(idx), realId);
                            }
                            resolveDocumentIdsAsync(indexName, spaceName, docIds, idx + 1, resolved, listener);
                        },
                        listener::onFailure));
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
            return (String) doc.get(Constants.KEY_ID);
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
    public String findDocumentId(String indexName, String spaceName, String documentId) {
        try {
            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
            sourceBuilder.query(
                    QueryBuilders.boolQuery()
                            .must(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName))
                            .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_ID, documentId)));
            sourceBuilder.size(1);
            sourceBuilder.fetchSource(false); // We only need the _id
            searchRequest.source(sourceBuilder);

            SearchResponse response =
                    this.offloadBlocking(() -> this.client.search(searchRequest).actionGet());
            if (response.getHits().getTotalHits().value() > 0) {
                return response.getHits().getAt(0).getId();
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_FIND_DOCUMENT_ID_FAILED, spaceName, documentId, e.getMessage());
        }
        return null;
    }

    /**
     * Asynchronously retrieves the policy document for a given space.
     *
     * @param space The space of the policy document.
     * @param listener receives the policy as a Map, or null if not found.
     */
    public void getPolicyAsync(String space, ActionListener<Map<String, Object>> listener) {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space));
        sourceBuilder.size(1);
        searchRequest.source(sourceBuilder);

        this.client.search(
                searchRequest,
                ActionListener.wrap(
                        response -> {
                            if (response.getHits().getTotalHits().value() > 0) {
                                SearchHit hit = response.getHits().getAt(0);
                                listener.onResponse(hit.getSourceAsMap());
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        e -> {
                            log.error(Constants.E_LOG_GET_POLICY_FAILED, space, e.getMessage());
                            listener.onFailure(
                                    new IOException("Failed to retrieve policy: " + e.getMessage(), e));
                        }));
    }

    /**
     * Asynchronously finds the real _id of a document given its logical document.id and space.
     *
     * @param indexName The index to search.
     * @param spaceName The space name.
     * @param documentId The logical document ID.
     * @param listener receives the real _id, or null if not found.
     */
    public void findDocumentIdAsync(
            String indexName, String spaceName, String documentId, ActionListener<String> listener) {
        SearchRequest searchRequest = new SearchRequest(indexName);
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName))
                        .must(QueryBuilders.termQuery(Constants.Q_DOCUMENT_ID, documentId)));
        sourceBuilder.size(1);
        sourceBuilder.fetchSource(false);
        searchRequest.source(sourceBuilder);

        this.client.search(
                searchRequest,
                ActionListener.wrap(
                        response -> {
                            if (response.getHits().getTotalHits().value() > 0) {
                                listener.onResponse(response.getHits().getAt(0).getId());
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        e -> {
                            log.error(
                                    Constants.E_LOG_FIND_DOCUMENT_ID_FAILED, spaceName, documentId, e.getMessage());
                            listener.onFailure(e);
                        }));
    }

    /**
     * This is a wrapper for its overloaded counterpart, intended to provide a default behavior that
     * processes only production spaces.
     *
     * @return The set of space names whose aggregate hashes changed.
     */
    public Set<String> calculateAndUpdate() {

        List<String> productionSpaces =
                Arrays.stream(Space.values())
                        .filter(space -> !space.equals(Space.DRAFT) && !space.equals(Space.TEST))
                        .map(Space::toString)
                        .collect(Collectors.toList());

        return this.calculateAndUpdate(productionSpaces);
    }

    /**
     * Calculates and updates the aggregate hash for all policies in the given consumer context. This
     * method was merged from SpaceService.
     *
     * @param targetSpaces The list of target spaces to process.
     * @return The set of space names whose aggregate hashes changed.
     */
    public Set<String> calculateAndUpdate(List<String> targetSpaces) {
        Set<String> changedSpaces = new HashSet<>();
        try {
            if (!this.client.admin().indices().prepareExists(Constants.INDEX_POLICIES).get().isExists()) {
                log.warn(Constants.W_LOG_POLICY_INDEX_MISSING, Constants.INDEX_POLICIES);
                return changedSpaces;
            }

            SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
            searchRequest.source().query(QueryBuilders.matchAllQuery()).size(10000);
            SearchResponse response = this.client.search(searchRequest).actionGet();

            BulkRequest bulkUpdateRequest = new BulkRequest();

            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> source = hit.getSourceAsMap();

                @SuppressWarnings("unchecked")
                Map<String, Object> space = (Map<String, Object>) source.get(Constants.KEY_SPACE);
                String spaceName = null;
                if (space != null) {
                    spaceName = (String) space.get(Constants.KEY_NAME);
                    // Check if the policy is in one of the target spaces
                    if (!targetSpaces.contains(spaceName)) {
                        continue;
                    }
                    log.debug(Constants.D_LOG_RECALCULATING_HASH, hit.getId(), spaceName);
                }

                List<String> spaceHashes = new ArrayList<>();
                spaceHashes.add(Resource.extractHash(source));

                @SuppressWarnings("unchecked")
                Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
                if (document != null && document.containsKey(Constants.KEY_INTEGRATIONS)) {
                    @SuppressWarnings("unchecked")
                    List<String> integrationIds = (List<String>) document.get(Constants.KEY_INTEGRATIONS);

                    for (String integrationId : integrationIds) {
                        Map<String, Object> integrationSource =
                                this.getDocumentSource(Constants.INDEX_INTEGRATIONS, integrationId);
                        if (integrationSource == null) {
                            continue;
                        }

                        spaceHashes.add(Resource.extractHash(integrationSource));

                        @SuppressWarnings("unchecked")
                        Map<String, Object> integration =
                                (Map<String, Object>) integrationSource.get(Constants.KEY_DOCUMENT);
                        if (integration != null) {
                            this.addHashes(
                                    integration, Constants.KEY_DECODERS, Constants.INDEX_DECODERS, spaceHashes);
                            this.addHashes(integration, Constants.KEY_KVDBS, Constants.INDEX_KVDBS, spaceHashes);
                            this.addHashes(integration, Constants.KEY_RULES, Constants.INDEX_RULES, spaceHashes);
                        }
                    }
                }

                // Adding filter hashes that are referenced in the policy
                if (document != null && document.containsKey(Constants.KEY_FILTERS)) {
                    @SuppressWarnings("unchecked")
                    List<String> filterIds = (List<String>) document.get(Constants.KEY_FILTERS);

                    for (String filterId : filterIds) {
                        Map<String, Object> filterSource =
                                this.getDocumentSource(Constants.INDEX_FILTERS, filterId);
                        if (filterSource != null) {
                            spaceHashes.add(Resource.extractHash(filterSource));
                        }
                    }
                }

                String spaceHash = Resource.computeSha256(String.join("", spaceHashes));

                Map<String, Object> updateMap = new HashMap<>();
                @SuppressWarnings("unchecked")
                Map<String, Object> spaceMap =
                        (Map<String, Object>) source.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                @SuppressWarnings("unchecked")
                Map<String, Object> hashMap =
                        (Map<String, Object>) spaceMap.getOrDefault(Constants.KEY_HASH, new HashMap<>());

                // Track spaces whose aggregate hash changed
                String oldHash = (String) hashMap.getOrDefault(Constants.KEY_SHA256, "");
                if (spaceName != null && !spaceHash.equals(oldHash)) {
                    changedSpaces.add(spaceName);
                }

                hashMap.put(Constants.KEY_SHA256, spaceHash);
                spaceMap.put(Constants.KEY_HASH, hashMap);
                updateMap.put(Constants.KEY_SPACE, spaceMap);

                bulkUpdateRequest.add(
                        new UpdateRequest(Constants.INDEX_POLICIES, hit.getId())
                                .doc(updateMap, XContentType.JSON));
            }

            if (bulkUpdateRequest.numberOfActions() > 0) {
                bulkUpdateRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                BulkResponse bulkResponse = this.client.bulk(bulkUpdateRequest).actionGet();
                if (bulkResponse.hasFailures()) {
                    log.error(Constants.E_LOG_BULK_UPDATE_HASHES_FAILED, bulkResponse.buildFailureMessage());
                }
            }

            if (!changedSpaces.isEmpty()) {
                log.info(Constants.I_LOG_CONTENT_HASH_CHANGED, changedSpaces);
            }

        } catch (Exception e) {
            log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
        }
        return changedSpaces;
    }

    /**
     * Asynchronously calculates and updates the aggregate hash for all policies in the given spaces.
     *
     * @param targetSpaces The list of target spaces to process.
     * @param listener The listener to notify with the set of changed space names.
     */
    public void calculateAndUpdateAsync(
            List<String> targetSpaces, ActionListener<Set<String>> listener) {
        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(Constants.INDEX_POLICIES),
                        ActionListener.wrap(
                                existsResponse -> {
                                    if (!existsResponse.isExists()) {
                                        log.warn(Constants.W_LOG_POLICY_INDEX_MISSING, Constants.INDEX_POLICIES);
                                        listener.onResponse(new HashSet<>());
                                        return;
                                    }
                                    searchPoliciesAndProcessAsync(targetSpaces, listener);
                                },
                                e -> {
                                    log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
                                    listener.onResponse(new HashSet<>());
                                }));
    }

    private void searchPoliciesAndProcessAsync(
            List<String> targetSpaces, ActionListener<Set<String>> listener) {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
        searchRequest.source().query(QueryBuilders.matchAllQuery()).size(10000);

        this.client.search(
                searchRequest,
                ActionListener.wrap(
                        response -> {
                            Set<String> changedSpaces = new HashSet<>();
                            BulkRequest bulkUpdateRequest = new BulkRequest();
                            SearchHit[] hits = response.getHits().getHits();
                            processHitsAsync(
                                    hits,
                                    0,
                                    targetSpaces,
                                    bulkUpdateRequest,
                                    changedSpaces,
                                    ActionListener.wrap(
                                            v -> executeBulkUpdateAsync(bulkUpdateRequest, changedSpaces, listener),
                                            e -> {
                                                log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
                                                listener.onResponse(changedSpaces);
                                            }));
                        },
                        e -> {
                            log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
                            listener.onResponse(new HashSet<>());
                        }));
    }

    @SuppressWarnings("unchecked")
    private void processHitsAsync(
            SearchHit[] hits,
            int idx,
            List<String> targetSpaces,
            BulkRequest bulkUpdateRequest,
            Set<String> changedSpaces,
            ActionListener<Void> listener) {
        if (idx >= hits.length) {
            listener.onResponse(null);
            return;
        }

        SearchHit hit = hits[idx];
        Map<String, Object> source = hit.getSourceAsMap();
        Map<String, Object> space = (Map<String, Object>) source.get(Constants.KEY_SPACE);
        String spaceName = null;
        if (space != null) {
            spaceName = (String) space.get(Constants.KEY_NAME);
            if (!targetSpaces.contains(spaceName)) {
                processHitsAsync(hits, idx + 1, targetSpaces, bulkUpdateRequest, changedSpaces, listener);
                return;
            }
            log.debug(Constants.D_LOG_RECALCULATING_HASH, hit.getId(), spaceName);
        }

        List<String> spaceHashes = new ArrayList<>();
        spaceHashes.add(Resource.extractHash(source));

        Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
        List<String> integrationIds =
                (document != null && document.containsKey(Constants.KEY_INTEGRATIONS))
                        ? (List<String>) document.get(Constants.KEY_INTEGRATIONS)
                        : Collections.emptyList();
        List<String> filterIds =
                (document != null && document.containsKey(Constants.KEY_FILTERS))
                        ? (List<String>) document.get(Constants.KEY_FILTERS)
                        : Collections.emptyList();

        final String finalSpaceName = spaceName;
        collectIntegrationHashesAsync(
                integrationIds,
                0,
                spaceHashes,
                ActionListener.wrap(
                        v ->
                                collectResourceHashesAsync(
                                        filterIds,
                                        0,
                                        Constants.INDEX_FILTERS,
                                        spaceHashes,
                                        ActionListener.wrap(
                                                v2 -> {
                                                    finalizeHitHash(
                                                            hit,
                                                            source,
                                                            finalSpaceName,
                                                            spaceHashes,
                                                            bulkUpdateRequest,
                                                            changedSpaces);
                                                    processHitsAsync(
                                                            hits,
                                                            idx + 1,
                                                            targetSpaces,
                                                            bulkUpdateRequest,
                                                            changedSpaces,
                                                            listener);
                                                },
                                                listener::onFailure)),
                        listener::onFailure));
    }

    @SuppressWarnings("unchecked")
    private void finalizeHitHash(
            SearchHit hit,
            Map<String, Object> source,
            String spaceName,
            List<String> spaceHashes,
            BulkRequest bulkUpdateRequest,
            Set<String> changedSpaces) {
        String spaceHash = Resource.computeSha256(String.join("", spaceHashes));

        Map<String, Object> updateMap = new HashMap<>();
        Map<String, Object> spaceMap =
                (Map<String, Object>) source.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
        Map<String, Object> hashMap =
                (Map<String, Object>) spaceMap.getOrDefault(Constants.KEY_HASH, new HashMap<>());

        String oldHash = (String) hashMap.getOrDefault(Constants.KEY_SHA256, "");
        if (spaceName != null && !spaceHash.equals(oldHash)) {
            changedSpaces.add(spaceName);
        }

        hashMap.put(Constants.KEY_SHA256, spaceHash);
        spaceMap.put(Constants.KEY_HASH, hashMap);
        updateMap.put(Constants.KEY_SPACE, spaceMap);

        bulkUpdateRequest.add(
                new UpdateRequest(Constants.INDEX_POLICIES, hit.getId()).doc(updateMap, XContentType.JSON));
    }

    @SuppressWarnings("unchecked")
    private void collectIntegrationHashesAsync(
            List<String> integrationIds,
            int idx,
            List<String> spaceHashes,
            ActionListener<Void> listener) {
        if (idx >= integrationIds.size()) {
            listener.onResponse(null);
            return;
        }

        String integrationId = integrationIds.get(idx);
        getDocumentSourceAsync(
                Constants.INDEX_INTEGRATIONS,
                integrationId,
                ActionListener.wrap(
                        integrationSource -> {
                            if (integrationSource == null) {
                                collectIntegrationHashesAsync(integrationIds, idx + 1, spaceHashes, listener);
                                return;
                            }

                            spaceHashes.add(Resource.extractHash(integrationSource));

                            Map<String, Object> integration =
                                    (Map<String, Object>) integrationSource.get(Constants.KEY_DOCUMENT);
                            if (integration == null) {
                                collectIntegrationHashesAsync(integrationIds, idx + 1, spaceHashes, listener);
                                return;
                            }

                            addHashesAsync(
                                    integration,
                                    Constants.KEY_DECODERS,
                                    Constants.INDEX_DECODERS,
                                    spaceHashes,
                                    ActionListener.wrap(
                                            v ->
                                                    addHashesAsync(
                                                            integration,
                                                            Constants.KEY_KVDBS,
                                                            Constants.INDEX_KVDBS,
                                                            spaceHashes,
                                                            ActionListener.wrap(
                                                                    v2 ->
                                                                            addHashesAsync(
                                                                                    integration,
                                                                                    Constants.KEY_RULES,
                                                                                    Constants.INDEX_RULES,
                                                                                    spaceHashes,
                                                                                    ActionListener.wrap(
                                                                                            v3 ->
                                                                                                    collectIntegrationHashesAsync(
                                                                                                            integrationIds,
                                                                                                            idx + 1,
                                                                                                            spaceHashes,
                                                                                                            listener),
                                                                                            listener::onFailure)),
                                                                    listener::onFailure)),
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    @SuppressWarnings("unchecked")
    private void addHashesAsync(
            Map<String, Object> integration,
            String resource,
            String resourceIndex,
            List<String> spaceHashes,
            ActionListener<Void> listener) {
        if (!integration.containsKey(resource)) {
            listener.onResponse(null);
            return;
        }
        List<String> resourceIds = (List<String>) integration.get(resource);
        collectResourceHashesAsync(resourceIds, 0, resourceIndex, spaceHashes, listener);
    }

    private void collectResourceHashesAsync(
            List<String> ids,
            int idx,
            String indexName,
            List<String> hashes,
            ActionListener<Void> listener) {
        if (idx >= ids.size()) {
            listener.onResponse(null);
            return;
        }
        getDocumentSourceAsync(
                indexName,
                ids.get(idx),
                ActionListener.wrap(
                        source -> {
                            if (source != null) {
                                hashes.add(Resource.extractHash(source));
                            }
                            collectResourceHashesAsync(ids, idx + 1, indexName, hashes, listener);
                        },
                        listener::onFailure));
    }

    /**
     * Asynchronously retrieves the source document for a given document ID from the specified index.
     *
     * @param indexName The name of the index.
     * @param documentId The document ID.
     * @param listener The listener to notify with the source map, or null if not found.
     */
    public void getDocumentSourceAsync(
            String indexName, String documentId, ActionListener<Map<String, Object>> listener) {
        this.client.get(
                new GetRequest(indexName, documentId),
                ActionListener.wrap(
                        response -> {
                            if (response.isExists()) {
                                listener.onResponse(response.getSourceAsMap());
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        e -> {
                            log.warn(
                                    Constants.W_LOG_RETRIEVE_DOCUMENT_FAILED, documentId, indexName, e.getMessage());
                            listener.onResponse(null);
                        }));
    }

    private void executeBulkUpdateAsync(
            BulkRequest bulkUpdateRequest,
            Set<String> changedSpaces,
            ActionListener<Set<String>> listener) {
        if (bulkUpdateRequest.numberOfActions() == 0) {
            listener.onResponse(changedSpaces);
            return;
        }
        bulkUpdateRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        this.client.bulk(
                bulkUpdateRequest,
                ActionListener.wrap(
                        bulkResponse -> {
                            if (bulkResponse.hasFailures()) {
                                log.error(
                                        Constants.E_LOG_BULK_UPDATE_HASHES_FAILED, bulkResponse.buildFailureMessage());
                            }
                            if (!changedSpaces.isEmpty()) {
                                log.info(Constants.I_LOG_CONTENT_HASH_CHANGED, changedSpaces);
                            }
                            listener.onResponse(changedSpaces);
                        },
                        e -> {
                            log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
                            listener.onResponse(changedSpaces);
                        }));
    }

    /**
     * Adds hashes from resources of a specific type within an integration to the hash list. This
     * method was merged from SpaceService.
     *
     * @param integration The integration document.
     * @param resource The resource type (decoders, kvdbs, rules).
     * @param resourceIndex The index containing the resources.
     * @param spaceHashes The list to add hashes to.
     */
    private void addHashes(
            Map<String, Object> integration,
            String resource,
            String resourceIndex,
            List<String> spaceHashes) {
        if (integration.containsKey(resource)) {
            @SuppressWarnings("unchecked")
            List<String> resourceIds = (List<String>) integration.get(resource);
            for (String id : resourceIds) {
                Map<String, Object> resourceSource = this.getDocumentSource(resourceIndex, id);
                if (resourceSource != null) {
                    spaceHashes.add(Resource.extractHash(resourceSource));
                }
            }
        }
    }

    /**
     * Retrieves the source document for a given document ID from the specified index. This method was
     * moved from IndexHelper.
     *
     * @param indexName The name of the index.
     * @param documentId The document ID.
     * @return The document source as a Map, or null if not found.
     */
    public Map<String, Object> getDocumentSource(String indexName, String documentId) {
        try {
            GetRequest request = new GetRequest(indexName, documentId);
            GetResponse response = this.client.get(request).actionGet();
            if (response.isExists()) {
                return response.getSourceAsMap();
            }
        } catch (Exception e) {
            log.warn(Constants.W_LOG_RETRIEVE_DOCUMENT_FAILED, documentId, indexName, e.getMessage());
        }
        return null;
    }

    /**
     * Retrieves the set of known enrichment types for validation. This method dynamically fetches the
     * enrichment types from the IOC type hashes document in the IOC index, allowing for flexible
     * validation without hardcoding enrichment types. It also includes a special case for 'geo'
     * enrichment type which is not listed in the IOC type hashes document but should be allowed.
     *
     * @return A set of known enrichment types.
     */
    public Set<String> getKnownEnrichmentTypes() {
        // Get known enrichment types for validation dynamically from the IoC type hashes document
        Set<String> knownEnrichmentTypes = new HashSet<>();
        // 'geo' is a special case enrichment type that is not listed in the IOC type hashes document,
        // but should be allowed
        knownEnrichmentTypes.add("geo");
        try {
            GetRequest getRequest =
                    new GetRequest().index(Constants.INDEX_IOCS).id(Constants.IOC_TYPE_HASHES_ID);
            GetResponse response =
                    this.client
                            .get(getRequest)
                            .actionGet(PluginSettings.getInstance().getClientTimeout(), TimeUnit.SECONDS);

            if (response != null && response.isExists()) {
                JsonNode jsonNode =
                        this.objectMapper.valueToTree(response.getSourceAsMap().get(Constants.KEY_TYPE_HASHES));
                if (jsonNode != null && jsonNode.isObject()) {
                    Iterator<String> fieldNames = jsonNode.fieldNames();
                    while (fieldNames.hasNext()) {
                        knownEnrichmentTypes.add(fieldNames.next());
                    }
                }
            } else {
                log.warn(Constants.W_LOG_IOC_TYPE_HASHES_NOT_FOUND);
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_RETRIEVE_ENRICHMENT_TYPES_FAILED, e.getMessage());
        }
        return knownEnrichmentTypes;
    }

    /**
     * Returns {@code true} when the given space already contains at least one document in any of the
     * engine-related indices (decoders, kvdbs, filters).
     *
     * <p>Used by the promote action to determine whether the engine must be invoked even when the
     * promotion changeset carries no engine resources — because the resulting destination space will
     * still contain engine resources from prior promotions.
     *
     * <p>Each index is queried with a single-hit term search (size=1) so the cost is at most three
     * cheap reads regardless of the number of documents in the space.
     *
     * @param space The target space to check.
     * @return true if the space holds at least one decoder, kvdb, or filter.
     */
    public boolean hasEngineResources(Space space) {
        for (String index :
                List.of(Constants.INDEX_DECODERS, Constants.INDEX_KVDBS, Constants.INDEX_FILTERS)) {
            try {
                if (!this.client.admin().indices().prepareExists(index).get().isExists()) {
                    continue;
                }
                SearchRequest searchRequest = new SearchRequest(index);
                searchRequest
                        .source()
                        .query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()))
                        .size(1);
                SearchResponse response = this.client.search(searchRequest).actionGet();
                if (response.getHits().getTotalHits().value() > 0) {
                    return true;
                }
            } catch (Exception e) {
                log.warn(Constants.W_LOG_CHECK_ENGINE_RESOURCES_FAILED, space, index, e.getMessage());
            }
        }
        return false;
    }

    /**
     * Asynchronously checks whether the given space contains at least one document in any of the
     * engine-related indices (decoders, kvdbs, filters).
     *
     * @param space The target space to check.
     * @param listener receives true if the space holds at least one decoder, kvdb, or filter.
     */
    public void hasEngineResourcesAsync(Space space, ActionListener<Boolean> listener) {
        List<String> indices =
                List.of(Constants.INDEX_DECODERS, Constants.INDEX_KVDBS, Constants.INDEX_FILTERS);
        checkEngineIndexAsync(space, indices, 0, listener);
    }

    private void checkEngineIndexAsync(
            Space space, List<String> indices, int idx, ActionListener<Boolean> listener) {
        if (idx >= indices.size()) {
            listener.onResponse(false);
            return;
        }
        String index = indices.get(idx);
        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(index),
                        ActionListener.wrap(
                                existsResponse -> {
                                    if (!existsResponse.isExists()) {
                                        checkEngineIndexAsync(space, indices, idx + 1, listener);
                                        return;
                                    }
                                    SearchRequest searchRequest = new SearchRequest(index);
                                    searchRequest
                                            .source()
                                            .query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()))
                                            .size(1);
                                    this.client.search(
                                            searchRequest,
                                            ActionListener.wrap(
                                                    response -> {
                                                        if (response.getHits().getTotalHits().value() > 0) {
                                                            listener.onResponse(true);
                                                        } else {
                                                            checkEngineIndexAsync(space, indices, idx + 1, listener);
                                                        }
                                                    },
                                                    e -> {
                                                        log.warn(
                                                                Constants.W_LOG_CHECK_ENGINE_RESOURCES_FAILED,
                                                                space,
                                                                index,
                                                                e.getMessage());
                                                        checkEngineIndexAsync(space, indices, idx + 1, listener);
                                                    }));
                                },
                                e -> {
                                    log.warn(
                                            Constants.W_LOG_CHECK_ENGINE_RESOURCES_FAILED, space, index, e.getMessage());
                                    checkEngineIndexAsync(space, indices, idx + 1, listener);
                                }));
    }
}
