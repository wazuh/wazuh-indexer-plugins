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
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/** Service for retrieving resource information based on their Space. */
public class SpaceService {
    private static final Logger log = LogManager.getLogger(SpaceService.class);

    private static final FetchSourceContext HASH_ONLY_SOURCE =
            new FetchSourceContext(true, new String[] {Constants.Q_HASH}, new String[0]);

    private static final FetchSourceContext INTEGRATION_HASH_SOURCE =
            new FetchSourceContext(
                    true,
                    new String[] {Constants.Q_HASH, "document.rules", "document.decoders", "document.kvdbs"},
                    new String[0]);

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
     * @param space The space to wipe.
     * @param listener notified on completion or failure.
     */
    public void deleteSpaceResources(Space space, ActionListener<Void> listener) {
        String spaceName = space.toString();
        List<String> indexNames = new ArrayList<>(Constants.RESOURCE_INDICES.values());
        BulkRequest bulkRequest = new BulkRequest();
        collectDeleteRequestsAsync(
                spaceName,
                indexNames,
                0,
                bulkRequest,
                ActionListener.wrap(
                        v -> {
                            if (bulkRequest.numberOfActions() == 0) {
                                listener.onResponse(null);
                                return;
                            }
                            bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                            this.client.bulk(
                                    bulkRequest,
                                    ActionListener.wrap(
                                            bulkResponse -> {
                                                if (bulkResponse.hasFailures()) {
                                                    listener.onFailure(
                                                            new IOException(
                                                                    "Bulk deletion failed: " + bulkResponse.buildFailureMessage()));
                                                } else {
                                                    listener.onResponse(null);
                                                }
                                            },
                                            listener::onFailure));
                        },
                        e -> {
                            log.error(Constants.E_LOG_DELETE_SPACE_RESOURCES_FAILED, spaceName, e.getMessage());
                            listener.onFailure(
                                    new IOException("Failed to delete space resources: " + e.getMessage(), e));
                        }));
    }

    private void collectDeleteRequestsAsync(
            String spaceName,
            List<String> indexNames,
            int idx,
            BulkRequest bulkRequest,
            ActionListener<Void> listener) {
        if (idx >= indexNames.size()) {
            listener.onResponse(null);
            return;
        }
        String indexName = indexNames.get(idx);
        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(indexName),
                        ActionListener.wrap(
                                existsResponse -> {
                                    if (!existsResponse.isExists()) {
                                        collectDeleteRequestsAsync(
                                                spaceName, indexNames, idx + 1, bulkRequest, listener);
                                        return;
                                    }
                                    SearchRequest searchRequest = new SearchRequest(indexName);
                                    SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                                    // Selecting by space is also what keeps the user-overrides registry
                                    // document alive: it carries no space.name on purpose. Widening this to
                                    // match every document in the index would delete it, and silently lose
                                    // the user's policy settings and the filters they created.
                                    sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName));
                                    sourceBuilder.size(10000);
                                    sourceBuilder.fetchSource(false);
                                    searchRequest.source(sourceBuilder);

                                    this.client.search(
                                            searchRequest,
                                            ActionListener.wrap(
                                                    searchResponse -> {
                                                        for (SearchHit hit : searchResponse.getHits().getHits()) {
                                                            bulkRequest.add(new DeleteRequest(indexName, hit.getId()));
                                                        }
                                                        collectDeleteRequestsAsync(
                                                                spaceName, indexNames, idx + 1, bulkRequest, listener);
                                                    },
                                                    e -> {
                                                        log.warn(
                                                                "Failed to search index [{}] for space [{}] during delete, skipping: {}",
                                                                indexName,
                                                                spaceName,
                                                                e.getMessage());
                                                        collectDeleteRequestsAsync(
                                                                spaceName, indexNames, idx + 1, bulkRequest, listener);
                                                    }));
                                },
                                e -> {
                                    log.warn(
                                            "Failed to check existence of index [{}] for space [{}] during delete, skipping: {}",
                                            indexName,
                                            spaceName,
                                            e.getMessage());
                                    collectDeleteRequestsAsync(spaceName, indexNames, idx + 1, bulkRequest, listener);
                                }));
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
     * @param listener notified on completion or failure.
     */
    public void initializeSpace(String spaceName, String documentId, ActionListener<Void> listener) {
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
            // Enabled by default for every space: draft and test must match, otherwise the
            // promote preview reports the "enabled" mismatch itself as an unpromoted change.
            policy.setEnabled(true);
            policy.setIndexUnclassifiedEvents(false);
            policy.setIndexDiscardedEvents(false);

            ObjectNode docNode = this.objectMapper.valueToTree(policy);
            Resource.nestMetadataFields(docNode);

            String docJson = this.objectMapper.writeValueAsString(docNode);
            String docHash = Resource.computeSha256(docJson);

            ObjectNode hashNode = this.objectMapper.createObjectNode().put(Constants.KEY_SHA256, docHash);
            ObjectNode spaceNode = this.objectMapper.createObjectNode();
            spaceNode.put(Constants.KEY_NAME, spaceName);
            spaceNode.set(Constants.KEY_HASH, hashNode.deepCopy());

            ObjectNode source = this.objectMapper.createObjectNode();
            source.set(Constants.KEY_DOCUMENT, docNode);
            source.set(Constants.KEY_SPACE, spaceNode);
            source.set(Constants.KEY_HASH, hashNode);

            IndexRequest request =
                    new IndexRequest(Constants.INDEX_POLICIES)
                            .id(spaceDocId)
                            .source(this.objectMapper.writeValueAsString(source), XContentType.JSON)
                            .opType(DocWriteRequest.OpType.CREATE)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

            this.client.index(
                    request,
                    ActionListener.wrap(
                            indexResponse -> {
                                log.info(Constants.I_LOG_SPACE_INITIALIZED, spaceName);
                                listener.onResponse(null);
                            },
                            e -> {
                                if (e instanceof VersionConflictEngineException) {
                                    log.debug(Constants.D_LOG_SPACE_ALREADY_INITIALIZED, spaceName);
                                } else {
                                    log.error(Constants.E_LOG_INITIALIZE_SPACE_FAILED, spaceName, e.getMessage());
                                }
                                listener.onResponse(null);
                            }));
        } catch (Exception e) {
            log.error(Constants.E_LOG_INITIALIZE_SPACE_FAILED, spaceName, e.getMessage());
            listener.onResponse(null);
        }
    }

    /**
     * Seeds the default space policy documents (draft, test, custom) in the policies index if they do
     * not already exist.
     *
     * <p>All three share one deterministic policy id so they stay linked, and each write goes through
     * {@link #initializeSpace} which uses {@code opType=CREATE}. This makes the method idempotent and
     * safe to call repeatedly and concurrently across nodes: a duplicate write raises a {@link
     * VersionConflictEngineException} that is silently ignored.
     *
     * <p>It is invoked both from catalog-sync post-processing and unconditionally at plugin startup,
     * so the default spaces (and therefore the draft policy that custom-ruleset operations require)
     * exist even when catalog synchronization is disabled.
     *
     * @param listener notified once all three spaces have been processed.
     */
    public void initializeDefaultSpaces(ActionListener<Void> listener) {
        // Deterministic id shared across all default policies so they are linked; a name-based
        // UUID (v3) ensures every node derives the same id from the same seed.
        String sharedDocumentId =
                UUID.nameUUIDFromBytes("wazuh-default-policy".getBytes(StandardCharsets.UTF_8)).toString();

        List<String> spaces =
                List.of(Space.DRAFT.toString(), Space.TEST.toString(), Space.CUSTOM.toString());

        GroupedActionListener<Void> group =
                new GroupedActionListener<>(
                        ActionListener.wrap(ignored -> listener.onResponse(null), listener::onFailure),
                        spaces.size());

        spaces.forEach(space -> this.initializeSpace(space, sharedDocumentId, group));
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
     * Fetches all documents from a specific index that belong to a given space, keyed by document.id.
     *
     * @param indexName The index to search.
     * @param space The space to filter by.
     * @param listener receives a map of document.id to document content.
     */
    public void getResourcesBySpace(
            String indexName, Space space, ActionListener<Map<String, Map<String, Object>>> listener) {
        this.getResourcesBySpace(indexName, space, null, listener);
    }

    /**
     * Fetches documents from a specific index that belong to a given space, keyed by document.id,
     * returning only the specified source fields.
     *
     * @param indexName The index to search.
     * @param space The space to filter by.
     * @param includes Source fields to include (null for all fields).
     * @param listener receives a map of document.id to document content.
     */
    public void getResourcesBySpace(
            String indexName,
            Space space,
            String[] includes,
            ActionListener<Map<String, Map<String, Object>>> listener) {
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
                                    if (includes != null) {
                                        sourceBuilder.fetchSource(includes, null);
                                    }
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
    public void buildEnginePayload(
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
        getResourcesBySpace(
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
     * Asynchronously builds the engine payload for a full space without any modifications. This is
     * used to load an entire space into the Engine, such as the standard space after a CTI sync.
     *
     * @param spaceName The space name to build the payload for.
     * @param listener receives a JsonNode representing the engine payload.
     */
    public void buildEnginePayload(String spaceName, ActionListener<JsonNode> listener) {
        getPolicy(
                spaceName,
                ActionListener.wrap(
                        policyDocument ->
                                buildEnginePayload(
                                        policyDocument,
                                        spaceName,
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptyMap(),
                                        Collections.emptySet(),
                                        Collections.emptySet(),
                                        Collections.emptySet(),
                                        Collections.emptySet(),
                                        listener),
                        listener::onFailure));
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
     * Asynchronously retrieves the policy document for a given space.
     *
     * @param space The space of the policy document.
     * @param listener receives the policy as a Map, or null if not found.
     */
    public void getPolicy(String space, ActionListener<Map<String, Object>> listener) {
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
                            // A missing policies index or a cluster block (typically "state not
                            // recovered / initialized") is an expected pre-initialization state, not an
                            // operational error: every node reads policies from startup onwards.
                            // Callers still get the failure and decide.
                            if (ExceptionsHelper.unwrap(e, IndexNotFoundException.class) != null
                                    || ExceptionsHelper.unwrap(e, ClusterBlockException.class) != null) {
                                log.debug(Constants.D_LOG_POLICY_INDEX_NOT_READY, space, e.getMessage());
                            } else {
                                log.error(Constants.E_LOG_GET_POLICY_FAILED, space, e.getMessage());
                            }
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
     * Recalculates a space's aggregate hash if its policy document currently has none.
     *
     * @param space The space to check (e.g. {@code standard}).
     * @param listener The listener to notify with the set of changed space names; empty when no
     *     recalculation was needed or possible.
     */
    @SuppressWarnings("unchecked")
    public void recalculateSpaceHashIfMissing(String space, ActionListener<Set<String>> listener) {
        this.getPolicy(
                space,
                ActionListener.wrap(
                        policy -> {
                            if (policy == null) {
                                log.debug(Constants.D_LOG_SPACE_HASH_NO_POLICY, space);
                                listener.onResponse(new HashSet<>());
                                return;
                            }
                            Map<String, Object> spaceObject =
                                    (Map<String, Object>) policy.get(Constants.KEY_SPACE);
                            String hash = spaceObject == null ? "" : Resource.extractHash(spaceObject);
                            if (hash != null && !hash.isBlank()) {
                                log.debug(Constants.D_LOG_SPACE_HASH_PRESENT, space);
                                listener.onResponse(new HashSet<>());
                                return;
                            }
                            log.warn(Constants.W_LOG_SPACE_HASH_MISSING_RECALCULATING, space);
                            this.calculateAndUpdate(List.of(space), listener);
                        },
                        e -> {
                            log.warn(Constants.W_LOG_SPACE_HASH_CHECK_FAILED, space, e.getMessage());
                            listener.onResponse(new HashSet<>());
                        }));
    }

    /**
     * Asynchronously calculates and updates the aggregate hash for all policies in the given spaces.
     *
     * @param targetSpaces The list of target spaces to process.
     * @param listener The listener to notify with the set of changed space names.
     */
    public void calculateAndUpdate(List<String> targetSpaces, ActionListener<Set<String>> listener) {
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
        // Only actual policies. Every policy carries space.name -- it is how the wipe, getPolicy and
        // the promotion flow all find them -- so requiring it here keeps documents that merely live in
        // this index from being processed as if they were policies. The user-overrides registry is one
        // such document: it deliberately has no space.name, and without this filter it fell through the
        // space check below and had a meaningless space.hash written into it on every recalculation.
        searchRequest
                .source()
                .query(QueryBuilders.boolQuery().filter(QueryBuilders.existsQuery(Constants.Q_SPACE_NAME)))
                .size(10000);

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
        getDocumentSource(
                Constants.INDEX_INTEGRATIONS,
                integrationId,
                INTEGRATION_HASH_SOURCE,
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
        getDocumentSource(
                indexName,
                ids.get(idx),
                HASH_ONLY_SOURCE,
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
    public void getDocumentSource(
            String indexName, String documentId, ActionListener<Map<String, Object>> listener) {
        getDocumentSource(indexName, documentId, null, listener);
    }

    /**
     * Asynchronously retrieves a filtered source document for a given document ID.
     *
     * @param indexName The name of the index.
     * @param documentId The document ID.
     * @param fetchSourceContext Source filtering context, or null for full source.
     * @param listener The listener to notify with the source map, or null if not found.
     */
    public void getDocumentSource(
            String indexName,
            String documentId,
            FetchSourceContext fetchSourceContext,
            ActionListener<Map<String, Object>> listener) {
        GetRequest request = new GetRequest(indexName, documentId);
        if (fetchSourceContext != null) {
            request.fetchSourceContext(fetchSourceContext);
        }
        this.client.get(
                request,
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
