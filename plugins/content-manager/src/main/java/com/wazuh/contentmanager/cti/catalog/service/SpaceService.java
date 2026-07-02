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
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
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
import java.util.stream.Collectors;

import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;

/** Service for retrieving resource information based on their Space. */
public class SpaceService {
    private static final Logger log = LogManager.getLogger(SpaceService.class);

    private final Client client;
    private final ObjectMapper objectMapper;

    public SpaceService(Client client) {
        this.client = client;
        this.objectMapper = new ObjectMapper();
    }

    // ── deleteSpaceResources ──────────────────────────────────────────────

    /**
     * Deletes all documents related to a specific space across all resource indices.
     *
     * @param space The name of the space to wipe.
     * @param listener called with {@code null} on success or an exception on failure.
     */
    public void deleteSpaceResources(Space space, ActionListener<Void> listener) {
        String spaceName = space.toString();
        BulkRequest bulkRequest = new BulkRequest();
        Iterator<String> indexIterator = Constants.RESOURCE_INDICES.values().iterator();
        deleteSpaceResourcesNext(spaceName, indexIterator, bulkRequest, listener);
    }

    private void deleteSpaceResourcesNext(
            String spaceName,
            Iterator<String> indexIterator,
            BulkRequest bulkRequest,
            ActionListener<Void> listener) {
        if (!indexIterator.hasNext()) {
            executeBulkDelete(bulkRequest, spaceName, listener);
            return;
        }

        String indexName = indexIterator.next();
        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(indexName),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndicesExistsResponse existsResponse) {
                                if (!existsResponse.isExists()) {
                                    deleteSpaceResourcesNext(spaceName, indexIterator, bulkRequest, listener);
                                    return;
                                }

                                SearchRequest searchRequest = new SearchRequest(indexName);
                                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                                sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName));
                                sourceBuilder.size(10000);
                                sourceBuilder.fetchSource(false);
                                searchRequest.source(sourceBuilder);

                                client.search(
                                        searchRequest,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(SearchResponse response) {
                                                for (SearchHit hit : response.getHits().getHits()) {
                                                    bulkRequest.add(new DeleteRequest(indexName, hit.getId()));
                                                }
                                                deleteSpaceResourcesNext(spaceName, indexIterator, bulkRequest, listener);
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                log.error(
                                                        Constants.E_LOG_DELETE_SPACE_RESOURCES_FAILED,
                                                        spaceName,
                                                        e.getMessage());
                                                listener.onFailure(
                                                        new IOException(
                                                                "Failed to delete space resources: " + e.getMessage(), e));
                                            }
                                        });
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error(Constants.E_LOG_DELETE_SPACE_RESOURCES_FAILED, spaceName, e.getMessage());
                                listener.onFailure(e);
                            }
                        });
    }

    private void executeBulkDelete(
            BulkRequest bulkRequest, String spaceName, ActionListener<Void> listener) {
        if (bulkRequest.numberOfActions() == 0) {
            listener.onResponse(null);
            return;
        }
        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        this.client.bulk(
                bulkRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(BulkResponse response) {
                        if (response.hasFailures()) {
                            listener.onFailure(
                                    new IOException("Bulk deletion failed: " + response.buildFailureMessage()));
                        } else {
                            listener.onResponse(null);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(Constants.E_LOG_DELETE_SPACE_RESOURCES_FAILED, spaceName, e.getMessage());
                        listener.onFailure(
                                new IOException("Failed to delete space resources: " + e.getMessage(), e));
                    }
                });
    }

    // ── initializeSpace ───────────────────────────────────────────────────

    /**
     * Creates a single space policy document if it does not already exist.
     *
     * <p>Uses a deterministic, space-specific OpenSearch document ID so that {@link
     * DocWriteRequest.OpType#CREATE} acts as an atomic guard: if two nodes race on startup, the
     * second write raises a {@link VersionConflictEngineException} which is silently ignored.
     *
     * @param spaceName The space name.
     * @param documentId Shared policy ID stored inside the document to link all default spaces.
     * @param listener called with {@code null} on success or an exception on failure.
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

            this.client.index(
                    request,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexResponse response) {
                            log.info(Constants.I_LOG_SPACE_INITIALIZED, spaceName);
                            listener.onResponse(null);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            if (e instanceof VersionConflictEngineException) {
                                log.debug(Constants.D_LOG_SPACE_ALREADY_INITIALIZED, spaceName);
                                listener.onResponse(null);
                            } else {
                                log.error(Constants.E_LOG_INITIALIZE_SPACE_FAILED, spaceName, e.getMessage());
                                listener.onFailure(e);
                            }
                        }
                    });
        } catch (Exception e) {
            log.error(Constants.E_LOG_INITIALIZE_SPACE_FAILED, spaceName, e.getMessage());
            listener.onFailure(e);
        }
    }

    // ── getSpaceResources ─────────────────────────────────────────────────

    /**
     * Fetches all resources (document.id and Hash) for a given space.
     *
     * @param spaceName The space to filter by (e.g., "draft", "test")
     * @param listener called with a map where Key=ResourceType and Value=Map(document.id to Hash)
     */
    public void getSpaceResources(
            String spaceName, ActionListener<Map<String, Map<String, String>>> listener) {
        Map<String, Map<String, String>> spaceResources = new HashMap<>();
        Iterator<Map.Entry<String, String>> entryIterator =
                Constants.RESOURCE_INDICES.entrySet().iterator();
        getSpaceResourcesNext(spaceName, entryIterator, spaceResources, listener);
    }

    private void getSpaceResourcesNext(
            String spaceName,
            Iterator<Map.Entry<String, String>> entryIterator,
            Map<String, Map<String, String>> spaceResources,
            ActionListener<Map<String, Map<String, String>>> listener) {
        if (!entryIterator.hasNext()) {
            listener.onResponse(spaceResources);
            return;
        }

        Map.Entry<String, String> entry = entryIterator.next();
        String resourceType = entry.getKey();
        String indexName = entry.getValue();
        Map<String, String> items = new HashMap<>();

        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(indexName),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndicesExistsResponse existsResponse) {
                                if (!existsResponse.isExists()) {
                                    log.warn(
                                            Constants.W_LOG_FETCH_RESOURCE_TYPE_FAILED,
                                            resourceType,
                                            indexName,
                                            spaceName,
                                            "Index [" + indexName + "] not found.");
                                    spaceResources.put(resourceType, items);
                                    getSpaceResourcesNext(spaceName, entryIterator, spaceResources, listener);
                                    return;
                                }

                                SearchRequest searchRequest = new SearchRequest(indexName);
                                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                                sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName));
                                sourceBuilder.fetchSource(
                                        new String[] {Constants.Q_HASH, Constants.Q_DOCUMENT_ID}, null);
                                sourceBuilder.size(10000);
                                searchRequest.source(sourceBuilder);

                                client.search(
                                        searchRequest,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(SearchResponse response) {
                                                for (SearchHit hit : response.getHits().getHits()) {
                                                    String hash = Resource.extractHash(hit.getSourceAsMap());
                                                    String docId = getDocumentId(hit.getSourceAsMap());
                                                    if (docId != null) {
                                                        items.put(docId, hash);
                                                    }
                                                }
                                                spaceResources.put(resourceType, items);
                                                getSpaceResourcesNext(spaceName, entryIterator, spaceResources, listener);
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                log.warn(
                                                        Constants.W_LOG_FETCH_RESOURCE_TYPE_FAILED,
                                                        resourceType,
                                                        indexName,
                                                        spaceName,
                                                        e.getMessage());
                                                spaceResources.put(resourceType, items);
                                                getSpaceResourcesNext(spaceName, entryIterator, spaceResources, listener);
                                            }
                                        });
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.warn(
                                        Constants.W_LOG_FETCH_RESOURCE_TYPE_FAILED,
                                        resourceType,
                                        indexName,
                                        spaceName,
                                        e.getMessage());
                                spaceResources.put(resourceType, items);
                                getSpaceResourcesNext(spaceName, entryIterator, spaceResources, listener);
                            }
                        });
    }

    // ── promoteSpace ──────────────────────────────────────────────────────

    /**
     * Consolidates resources after validation by applying ADD/UPDATE operations.
     *
     * @param indexName The index to update.
     * @param resourcesToConsolidate Map of resource ID (document.id) to resource document.
     * @param targetSpace The target space name.
     * @param listener called with {@code null} on success or an exception on failure.
     */
    public void promoteSpace(
            String indexName,
            Map<String, Map<String, Object>> resourcesToConsolidate,
            String targetSpace,
            ActionListener<Void> listener) {
        BulkRequest bulkRequest = new BulkRequest();
        Iterator<Map.Entry<String, Map<String, Object>>> entryIterator =
                resourcesToConsolidate.entrySet().iterator();
        promoteSpaceNext(indexName, targetSpace, entryIterator, bulkRequest, listener);
    }

    private void promoteSpaceNext(
            String indexName,
            String targetSpace,
            Iterator<Map.Entry<String, Map<String, Object>>> entryIterator,
            BulkRequest bulkRequest,
            ActionListener<Void> listener) {
        if (!entryIterator.hasNext()) {
            if (bulkRequest.numberOfActions() > 0) {
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                this.client.bulk(
                        bulkRequest,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(BulkResponse response) {
                                if (response.hasFailures()) {
                                    listener.onFailure(
                                            new IOException(
                                                    "Bulk consolidation failed: " + response.buildFailureMessage()));
                                } else {
                                    listener.onResponse(null);
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error(Constants.E_LOG_CONSOLIDATE_RESOURCES_FAILED, e.getMessage());
                                listener.onFailure(
                                        new IOException("Failed to consolidate resources: " + e.getMessage(), e));
                            }
                        });
            } else {
                listener.onResponse(null);
            }
            return;
        }

        Map.Entry<String, Map<String, Object>> entry = entryIterator.next();
        String docId = entry.getKey();
        Map<String, Object> doc = entry.getValue();

        @SuppressWarnings("unchecked")
        Map<String, String> spaceMap =
                (Map<String, String>) doc.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
        spaceMap.put(Constants.KEY_NAME, targetSpace);
        doc.put(Constants.KEY_SPACE, spaceMap);

        this.findDocumentId(
                indexName,
                targetSpace,
                docId,
                ActionListener.wrap(
                        targetId -> {
                            try {
                                IndexRequest indexRequest = new IndexRequest(indexName);
                                if (targetId != null) {
                                    indexRequest.id(targetId);
                                }
                                indexRequest.source(this.objectMapper.writeValueAsString(doc), XContentType.JSON);
                                bulkRequest.add(indexRequest);
                                promoteSpaceNext(indexName, targetSpace, entryIterator, bulkRequest, listener);
                            } catch (Exception e) {
                                log.error(Constants.E_LOG_CONSOLIDATE_RESOURCES_FAILED, e.getMessage());
                                listener.onFailure(
                                        new IOException("Failed to consolidate resources: " + e.getMessage(), e));
                            }
                        },
                        e -> {
                            log.error(Constants.E_LOG_CONSOLIDATE_RESOURCES_FAILED, e.getMessage());
                            listener.onFailure(
                                    new IOException("Failed to consolidate resources: " + e.getMessage(), e));
                        }));
    }

    // ── getResourcesBySpace ───────────────────────────────────────────────

    /**
     * Fetches all documents from a specific index that belong to a given space.
     *
     * @param indexName The index to search.
     * @param space The space to filter by.
     * @param listener called with a map of document.id to document content.
     */
    public void getResourcesBySpace(
            String indexName, Space space, ActionListener<Map<String, Map<String, Object>>> listener) {
        Map<String, Map<String, Object>> resources = new HashMap<>();

        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(indexName),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndicesExistsResponse existsResponse) {
                                if (!existsResponse.isExists()) {
                                    listener.onResponse(resources);
                                    return;
                                }
                                SearchRequest searchRequest = new SearchRequest(indexName);
                                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                                sourceBuilder.query(
                                        QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()));
                                sourceBuilder.size(10000);
                                searchRequest.source(sourceBuilder);

                                client.search(
                                        searchRequest,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(SearchResponse response) {
                                                for (SearchHit hit : response.getHits().getHits()) {
                                                    String docId = getDocumentId(hit.getSourceAsMap());
                                                    if (docId != null) {
                                                        resources.put(docId, hit.getSourceAsMap());
                                                    }
                                                }
                                                listener.onResponse(resources);
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                log.error(
                                                        Constants.E_LOG_FETCH_RESOURCES_FAILED,
                                                        indexName,
                                                        space,
                                                        e.getMessage());
                                                listener.onFailure(
                                                        new IOException("Failed to fetch resources: " + e.getMessage(), e));
                                            }
                                        });
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error(Constants.E_LOG_FETCH_RESOURCES_FAILED, indexName, space, e.getMessage());
                                listener.onFailure(
                                        new IOException("Failed to fetch resources: " + e.getMessage(), e));
                            }
                        });
    }

    // ── getResourceIdsBySpace ─────────────────────────────────────────────

    /**
     * Fetches only the document IDs from a specific index that belong to a given space.
     *
     * @param indexName The index to search.
     * @param space The space to filter by.
     * @param listener called with a set of document.id values.
     */
    public void getResourceIdsBySpace(
            String indexName, Space space, ActionListener<Set<String>> listener) {
        Set<String> ids = new HashSet<>();

        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(indexName),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndicesExistsResponse existsResponse) {
                                if (!existsResponse.isExists()) {
                                    listener.onResponse(ids);
                                    return;
                                }
                                SearchRequest searchRequest = new SearchRequest(indexName);
                                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                                sourceBuilder.query(
                                        QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()));
                                sourceBuilder.size(10000);
                                sourceBuilder.fetchSource(new String[] {Constants.Q_DOCUMENT_ID}, null);
                                searchRequest.source(sourceBuilder);

                                client.search(
                                        searchRequest,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(SearchResponse response) {
                                                for (SearchHit hit : response.getHits().getHits()) {
                                                    String docId = getDocumentId(hit.getSourceAsMap());
                                                    if (docId != null) {
                                                        ids.add(docId);
                                                    }
                                                }
                                                listener.onResponse(ids);
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                log.error(
                                                        Constants.E_LOG_FETCH_RESOURCES_FAILED,
                                                        indexName,
                                                        space,
                                                        e.getMessage());
                                                listener.onFailure(
                                                        new IOException("Failed to fetch resource IDs: " + e.getMessage(), e));
                                            }
                                        });
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error(Constants.E_LOG_FETCH_RESOURCES_FAILED, indexName, space, e.getMessage());
                                listener.onFailure(
                                        new IOException("Failed to fetch resource IDs: " + e.getMessage(), e));
                            }
                        });
    }

    // ── buildEnginePayload ────────────────────────────────────────────────

    /**
     * Builds the engine payload by gathering all required resources from the target space.
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
     * @param listener called with the engine payload JsonNode.
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

        this.getResourcesBySpace(
                Constants.INDEX_INTEGRATIONS,
                space,
                ActionListener.wrap(
                        targetIntegrations -> {
                            targetIntegrations.putAll(integrationsToApply);
                            for (String id : integrationsToDelete) targetIntegrations.remove(id);
                            resourcesNode.set(
                                    Constants.KEY_INTEGRATIONS, this.buildResourceArray(targetIntegrations));

                            this.getResourcesBySpace(
                                    Constants.INDEX_KVDBS,
                                    space,
                                    ActionListener.wrap(
                                            targetKvdbs -> {
                                                targetKvdbs.putAll(kvdbsToApply);
                                                for (String id : kvdbsToDelete) targetKvdbs.remove(id);
                                                resourcesNode.set(
                                                        Constants.KEY_KVDBS, this.buildResourceArray(targetKvdbs));

                                                this.getResourcesBySpace(
                                                        Constants.INDEX_DECODERS,
                                                        space,
                                                        ActionListener.wrap(
                                                                targetDecoders -> {
                                                                    targetDecoders.putAll(decodersToApply);
                                                                    for (String id : decodersToDelete) targetDecoders.remove(id);
                                                                    resourcesNode.set(
                                                                            Constants.KEY_DECODERS,
                                                                            this.buildResourceArray(targetDecoders));

                                                                    this.getResourcesBySpace(
                                                                            Constants.INDEX_FILTERS,
                                                                            space,
                                                                            ActionListener.wrap(
                                                                                    targetFilters -> {
                                                                                        targetFilters.putAll(filtersToApply);
                                                                                        for (String id : filtersToDelete)
                                                                                            targetFilters.remove(id);
                                                                                        resourcesNode.set(
                                                                                                Constants.KEY_FILTERS,
                                                                                                this.buildResourceArray(targetFilters));

                                                                                        fullPolicyNode.set(
                                                                                                Constants.KEY_RESOURCES, resourcesNode);
                                                                                        rootPayload.set(
                                                                                                Constants.KEY_FULL_POLICY, fullPolicyNode);
                                                                                        listener.onResponse(rootPayload);
                                                                                    },
                                                                                    listener::onFailure));
                                                                },
                                                                listener::onFailure));
                                            },
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    /**
     * Builds the engine payload for a full space without any modifications.
     *
     * @param spaceName The space name to build the payload for.
     * @param listener called with the engine payload JsonNode.
     */
    public void buildEnginePayload(String spaceName, ActionListener<JsonNode> listener) {
        this.getPolicy(
                spaceName,
                ActionListener.wrap(
                        policyDocument ->
                                this.buildEnginePayload(
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

    // ── getIndexForResourceType ───────────────────────────────────────────

    public String getIndexForResourceType(String resourceType) {
        return Constants.RESOURCE_INDICES.get(resourceType);
    }

    // ── getDocument ───────────────────────────────────────────────────────

    /**
     * Retrieves a document from the specified index by ID.
     *
     * @param indexName The name of the index to search.
     * @param id The document ID.
     * @param listener called with the document as a Map, or null if not found.
     */
    public void getDocument(
            String indexName, String id, ActionListener<Map<String, Object>> listener) {
        GetRequest request = new GetRequest(indexName, id);
        this.client.get(
                request,
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse response) {
                        if (response.isExists()) {
                            listener.onResponse(response.getSourceAsMap());
                        } else {
                            listener.onResponse(null);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(Constants.E_LOG_GET_DOCUMENT_FAILED, id, indexName, e.getMessage());
                        listener.onFailure(
                                new IOException("Failed to retrieve document: " + e.getMessage(), e));
                    }
                });
    }

    /**
     * Retrieves a document from the specified index by its logical ID (document.id) within a space.
     *
     * @param indexName The name of the index to search.
     * @param space The space name.
     * @param documentId The logical document ID.
     * @param listener called with the document as a Map, or null if not found.
     */
    public void getDocument(
            String indexName,
            String space,
            String documentId,
            ActionListener<Map<String, Object>> listener) {
        this.findDocumentId(
                indexName,
                space,
                documentId,
                ActionListener.wrap(
                        realId -> {
                            if (realId != null) {
                                this.getDocument(indexName, realId, listener);
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        listener::onFailure));
    }

    // ── getPolicy ─────────────────────────────────────────────────────────

    /**
     * Fetches the full policy document from the policies index by searching for the space.
     *
     * @param space The space of the policy document.
     * @param listener called with the policy document as a Map, or null if not found.
     */
    public void getPolicy(String space, ActionListener<Map<String, Object>> listener) {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space));
        sourceBuilder.size(1);
        searchRequest.source(sourceBuilder);

        this.client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.getHits().getTotalHits().value() > 0) {
                            listener.onResponse(response.getHits().getAt(0).getSourceAsMap());
                        } else {
                            listener.onResponse(null);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(Constants.E_LOG_GET_POLICY_FAILED, space, e.getMessage());
                        listener.onFailure(new IOException("Failed to retrieve policy: " + e.getMessage(), e));
                    }
                });
    }

    // ── deleteResources ───────────────────────────────────────────────────

    /**
     * Deletes resources from the target space after validation.
     *
     * @param indexName The index to delete from.
     * @param resourceIdsToDelete Set of resource IDs (document.id) to delete.
     * @param targetSpace The target space (for verification).
     * @param listener called with {@code null} on success or an exception on failure.
     */
    public void deleteResources(
            String indexName,
            Set<String> resourceIdsToDelete,
            String targetSpace,
            ActionListener<Void> listener) {
        BulkRequest bulkRequest = new BulkRequest();
        Iterator<String> idIterator = resourceIdsToDelete.iterator();
        deleteResourcesNext(indexName, targetSpace, idIterator, bulkRequest, listener);
    }

    private void deleteResourcesNext(
            String indexName,
            String targetSpace,
            Iterator<String> idIterator,
            BulkRequest bulkRequest,
            ActionListener<Void> listener) {
        if (!idIterator.hasNext()) {
            if (bulkRequest.numberOfActions() > 0) {
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                this.client.bulk(
                        bulkRequest,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(BulkResponse response) {
                                if (response.hasFailures()) {
                                    listener.onFailure(
                                            new IOException("Bulk deletion failed: " + response.buildFailureMessage()));
                                } else {
                                    listener.onResponse(null);
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error(Constants.E_LOG_DELETE_RESOURCES_FAILED, e.getMessage());
                                listener.onFailure(
                                        new IOException("Failed to delete resources: " + e.getMessage(), e));
                            }
                        });
            } else {
                listener.onResponse(null);
            }
            return;
        }

        String docId = idIterator.next();
        this.findDocumentId(
                indexName,
                targetSpace,
                docId,
                ActionListener.wrap(
                        targetId -> {
                            if (targetId != null) {
                                bulkRequest.add(new DeleteRequest(indexName, targetId));
                            } else {
                                log.warn(Constants.W_LOG_DOCUMENT_NOT_FOUND_FOR_DELETION, docId, targetSpace);
                            }
                            deleteResourcesNext(indexName, targetSpace, idIterator, bulkRequest, listener);
                        },
                        e -> {
                            log.error(Constants.E_LOG_DELETE_RESOURCES_FAILED, e.getMessage());
                            listener.onFailure(
                                    new IOException("Failed to delete resources: " + e.getMessage(), e));
                        }));
    }

    // ── getDocumentId (private helper, no client calls) ───────────────────

    @SuppressWarnings("unchecked")
    private String getDocumentId(Map<String, Object> source) {
        if (source != null && source.containsKey(Constants.KEY_DOCUMENT)) {
            Map<String, Object> doc = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
            return (String) doc.get(Constants.KEY_ID);
        }
        return null;
    }

    // ── findDocumentId ────────────────────────────────────────────────────

    /**
     * Finds the real _id of a document given its logical document.id and space.
     *
     * @param indexName The index to search.
     * @param spaceName The space name.
     * @param documentId The logical document ID.
     * @param listener called with the real _id, or null if not found.
     */
    public void findDocumentId(
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
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.getHits().getTotalHits().value() > 0) {
                            listener.onResponse(response.getHits().getAt(0).getId());
                        } else {
                            listener.onResponse(null);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(
                                Constants.E_LOG_FIND_DOCUMENT_ID_FAILED, spaceName, documentId, e.getMessage());
                        listener.onResponse(null);
                    }
                });
    }

    // ── calculateAndUpdate ────────────────────────────────────────────────

    /**
     * Calculates and updates the aggregate hash for all policies in production spaces.
     *
     * @param listener called with the set of space names whose aggregate hashes changed.
     */
    public void calculateAndUpdate(ActionListener<Set<String>> listener) {
        List<String> productionSpaces =
                Arrays.stream(Space.values())
                        .filter(space -> !space.equals(Space.DRAFT) && !space.equals(Space.TEST))
                        .map(Space::toString)
                        .collect(Collectors.toList());
        this.calculateAndUpdate(productionSpaces, listener);
    }

    /**
     * Calculates and updates the aggregate hash for all policies in the given spaces.
     *
     * @param targetSpaces The list of target spaces to process.
     * @param listener called with the set of space names whose aggregate hashes changed.
     */
    public void calculateAndUpdate(List<String> targetSpaces, ActionListener<Set<String>> listener) {
        Set<String> changedSpaces = new HashSet<>();

        try {
            this.client
                    .admin()
                    .indices()
                    .exists(
                            new IndicesExistsRequest(Constants.INDEX_POLICIES),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(IndicesExistsResponse existsResponse) {
                                    if (!existsResponse.isExists()) {
                                        log.warn(Constants.W_LOG_POLICY_INDEX_MISSING, Constants.INDEX_POLICIES);
                                        listener.onResponse(changedSpaces);
                                        return;
                                    }

                                    SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
                                    searchRequest.source().query(QueryBuilders.matchAllQuery()).size(10000);

                                    client.search(
                                            searchRequest,
                                            new ActionListener<>() {
                                                @Override
                                                public void onResponse(SearchResponse response) {
                                                    BulkRequest bulkUpdateRequest = new BulkRequest();
                                                    SearchHit[] hits = response.getHits().getHits();
                                                    processNextPolicyHit(
                                                            targetSpaces,
                                                            hits,
                                                            0,
                                                            changedSpaces,
                                                            bulkUpdateRequest,
                                                            () ->
                                                                    finishCalculateAndUpdate(
                                                                            bulkUpdateRequest, changedSpaces, listener));
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
                                                    listener.onResponse(changedSpaces);
                                                }
                                            });
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
                                    listener.onResponse(changedSpaces);
                                }
                            });
        } catch (Exception e) {
            log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
            listener.onResponse(changedSpaces);
        }
    }

    private void processNextPolicyHit(
            List<String> targetSpaces,
            SearchHit[] hits,
            int index,
            Set<String> changedSpaces,
            BulkRequest bulkUpdateRequest,
            Runnable onComplete) {
        if (index >= hits.length) {
            onComplete.run();
            return;
        }

        SearchHit hit = hits[index];
        Map<String, Object> source = hit.getSourceAsMap();

        @SuppressWarnings("unchecked")
        Map<String, Object> space = (Map<String, Object>) source.get(Constants.KEY_SPACE);
        String spaceName = null;
        if (space != null) {
            spaceName = (String) space.get(Constants.KEY_NAME);
            if (!targetSpaces.contains(spaceName)) {
                processNextPolicyHit(
                        targetSpaces, hits, index + 1, changedSpaces, bulkUpdateRequest, onComplete);
                return;
            }
            log.debug(Constants.D_LOG_RECALCULATING_HASH, hit.getId(), spaceName);
        }

        List<String> spaceHashes = new ArrayList<>();
        spaceHashes.add(Resource.extractHash(source));

        @SuppressWarnings("unchecked")
        Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);

        String finalSpaceName = spaceName;

        Runnable afterFilters =
                () -> {
                    String spaceHash = Resource.computeSha256(String.join("", spaceHashes));

                    Map<String, Object> updateMap = new HashMap<>();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> spaceMap =
                            (Map<String, Object>) source.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                    @SuppressWarnings("unchecked")
                    Map<String, Object> hashMap =
                            (Map<String, Object>) spaceMap.getOrDefault(Constants.KEY_HASH, new HashMap<>());

                    String oldHash = (String) hashMap.getOrDefault(Constants.KEY_SHA256, "");
                    if (finalSpaceName != null && !spaceHash.equals(oldHash)) {
                        changedSpaces.add(finalSpaceName);
                    }

                    hashMap.put(Constants.KEY_SHA256, spaceHash);
                    spaceMap.put(Constants.KEY_HASH, hashMap);
                    updateMap.put(Constants.KEY_SPACE, spaceMap);

                    bulkUpdateRequest.add(
                            new UpdateRequest(Constants.INDEX_POLICIES, hit.getId())
                                    .doc(updateMap, XContentType.JSON));

                    processNextPolicyHit(
                            targetSpaces, hits, index + 1, changedSpaces, bulkUpdateRequest, onComplete);
                };

        Runnable afterIntegrations =
                () -> {
                    if (document != null && document.containsKey(Constants.KEY_FILTERS)) {
                        @SuppressWarnings("unchecked")
                        List<String> filterIds = (List<String>) document.get(Constants.KEY_FILTERS);
                        processNextFilter(filterIds.iterator(), spaceHashes, afterFilters);
                    } else {
                        afterFilters.run();
                    }
                };

        if (document != null && document.containsKey(Constants.KEY_INTEGRATIONS)) {
            @SuppressWarnings("unchecked")
            List<String> integrationIds = (List<String>) document.get(Constants.KEY_INTEGRATIONS);
            processNextIntegration(integrationIds.iterator(), spaceHashes, afterIntegrations);
        } else {
            afterIntegrations.run();
        }
    }

    private void processNextIntegration(
            Iterator<String> idIterator, List<String> spaceHashes, Runnable onComplete) {
        if (!idIterator.hasNext()) {
            onComplete.run();
            return;
        }
        String integrationId = idIterator.next();
        this.getDocumentSource(
                Constants.INDEX_INTEGRATIONS,
                integrationId,
                ActionListener.wrap(
                        integrationSource -> {
                            if (integrationSource == null) {
                                processNextIntegration(idIterator, spaceHashes, onComplete);
                                return;
                            }
                            spaceHashes.add(Resource.extractHash(integrationSource));

                            @SuppressWarnings("unchecked")
                            Map<String, Object> integration =
                                    (Map<String, Object>) integrationSource.get(Constants.KEY_DOCUMENT);
                            if (integration == null) {
                                processNextIntegration(idIterator, spaceHashes, onComplete);
                                return;
                            }
                            this.addHashes(
                                    integration,
                                    Constants.KEY_DECODERS,
                                    Constants.INDEX_DECODERS,
                                    spaceHashes,
                                    ActionListener.wrap(
                                            v1 ->
                                                    this.addHashes(
                                                            integration,
                                                            Constants.KEY_KVDBS,
                                                            Constants.INDEX_KVDBS,
                                                            spaceHashes,
                                                            ActionListener.wrap(
                                                                    v2 ->
                                                                            this.addHashes(
                                                                                    integration,
                                                                                    Constants.KEY_RULES,
                                                                                    Constants.INDEX_RULES,
                                                                                    spaceHashes,
                                                                                    ActionListener.wrap(
                                                                                            v3 ->
                                                                                                    processNextIntegration(
                                                                                                            idIterator, spaceHashes, onComplete),
                                                                                            e ->
                                                                                                    processNextIntegration(
                                                                                                            idIterator, spaceHashes, onComplete))),
                                                                    e ->
                                                                            processNextIntegration(idIterator, spaceHashes, onComplete))),
                                            e -> processNextIntegration(idIterator, spaceHashes, onComplete)));
                        },
                        e -> processNextIntegration(idIterator, spaceHashes, onComplete)));
    }

    private void processNextFilter(
            Iterator<String> idIterator, List<String> spaceHashes, Runnable onComplete) {
        if (!idIterator.hasNext()) {
            onComplete.run();
            return;
        }
        String filterId = idIterator.next();
        this.getDocumentSource(
                Constants.INDEX_FILTERS,
                filterId,
                ActionListener.wrap(
                        filterSource -> {
                            if (filterSource != null) {
                                spaceHashes.add(Resource.extractHash(filterSource));
                            }
                            processNextFilter(idIterator, spaceHashes, onComplete);
                        },
                        e -> processNextFilter(idIterator, spaceHashes, onComplete)));
    }

    private void finishCalculateAndUpdate(
            BulkRequest bulkUpdateRequest,
            Set<String> changedSpaces,
            ActionListener<Set<String>> listener) {
        if (bulkUpdateRequest.numberOfActions() > 0) {
            bulkUpdateRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            this.client.bulk(
                    bulkUpdateRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(BulkResponse bulkResponse) {
                            if (bulkResponse.hasFailures()) {
                                log.error(
                                        Constants.E_LOG_BULK_UPDATE_HASHES_FAILED, bulkResponse.buildFailureMessage());
                            }
                            if (!changedSpaces.isEmpty()) {
                                log.info(Constants.I_LOG_CONTENT_HASH_CHANGED, changedSpaces);
                            }
                            listener.onResponse(changedSpaces);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error(Constants.E_LOG_CALCULATE_HASHES_FAILED, e.getMessage(), e);
                            listener.onResponse(changedSpaces);
                        }
                    });
        } else {
            if (!changedSpaces.isEmpty()) {
                log.info(Constants.I_LOG_CONTENT_HASH_CHANGED, changedSpaces);
            }
            listener.onResponse(changedSpaces);
        }
    }

    // ── addHashes ─────────────────────────────────────────────────────────

    private void addHashes(
            Map<String, Object> integration,
            String resource,
            String resourceIndex,
            List<String> spaceHashes,
            ActionListener<Void> listener) {
        if (!integration.containsKey(resource)) {
            listener.onResponse(null);
            return;
        }
        @SuppressWarnings("unchecked")
        List<String> resourceIds = (List<String>) integration.get(resource);
        addHashesNext(resourceIndex, resourceIds.iterator(), spaceHashes, listener);
    }

    private void addHashesNext(
            String resourceIndex,
            Iterator<String> idIterator,
            List<String> spaceHashes,
            ActionListener<Void> listener) {
        if (!idIterator.hasNext()) {
            listener.onResponse(null);
            return;
        }
        String id = idIterator.next();
        this.getDocumentSource(
                resourceIndex,
                id,
                ActionListener.wrap(
                        resourceSource -> {
                            if (resourceSource != null) {
                                spaceHashes.add(Resource.extractHash(resourceSource));
                            }
                            addHashesNext(resourceIndex, idIterator, spaceHashes, listener);
                        },
                        e -> addHashesNext(resourceIndex, idIterator, spaceHashes, listener)));
    }

    // ── getDocumentSource ─────────────────────────────────────────────────

    /**
     * Retrieves the source document for a given document ID from the specified index.
     *
     * @param indexName The name of the index.
     * @param documentId The document ID.
     * @param listener called with the document source as a Map, or null if not found.
     */
    public void getDocumentSource(
            String indexName, String documentId, ActionListener<Map<String, Object>> listener) {
        GetRequest request = new GetRequest(indexName, documentId);
        this.client.get(
                request,
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse response) {
                        if (response.isExists()) {
                            listener.onResponse(response.getSourceAsMap());
                        } else {
                            listener.onResponse(null);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.warn(
                                Constants.W_LOG_RETRIEVE_DOCUMENT_FAILED, documentId, indexName, e.getMessage());
                        listener.onResponse(null);
                    }
                });
    }

    // ── getKnownEnrichmentTypes ───────────────────────────────────────────

    /**
     * Retrieves the set of known enrichment types for validation.
     *
     * @param listener called with a set of known enrichment types.
     */
    public void getKnownEnrichmentTypes(ActionListener<Set<String>> listener) {
        Set<String> knownEnrichmentTypes = new HashSet<>();
        knownEnrichmentTypes.add("geo");

        GetRequest getRequest =
                new GetRequest().index(Constants.INDEX_IOCS).id(Constants.IOC_TYPE_HASHES_ID);
        this.client.get(
                getRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse response) {
                        if (response != null && response.isExists()) {
                            JsonNode jsonNode =
                                    objectMapper.valueToTree(
                                            response.getSourceAsMap().get(Constants.KEY_TYPE_HASHES));
                            if (jsonNode != null && jsonNode.isObject()) {
                                Iterator<String> fieldNames = jsonNode.fieldNames();
                                while (fieldNames.hasNext()) {
                                    knownEnrichmentTypes.add(fieldNames.next());
                                }
                            }
                        } else {
                            log.warn(Constants.W_LOG_IOC_TYPE_HASHES_NOT_FOUND);
                        }
                        listener.onResponse(knownEnrichmentTypes);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(Constants.E_LOG_RETRIEVE_ENRICHMENT_TYPES_FAILED, e.getMessage());
                        listener.onResponse(knownEnrichmentTypes);
                    }
                });
    }

    // ── hasEngineResources ────────────────────────────────────────────────

    /**
     * Returns whether the given space contains at least one document in any engine-related index.
     *
     * @param space The target space to check.
     * @param listener called with true if the space holds at least one decoder, kvdb, or filter.
     */
    public void hasEngineResources(Space space, ActionListener<Boolean> listener) {
        List<String> indices =
                List.of(Constants.INDEX_DECODERS, Constants.INDEX_KVDBS, Constants.INDEX_FILTERS);
        hasEngineResourcesNext(space, indices.iterator(), listener);
    }

    private void hasEngineResourcesNext(
            Space space, Iterator<String> indexIterator, ActionListener<Boolean> listener) {
        if (!indexIterator.hasNext()) {
            listener.onResponse(false);
            return;
        }

        String index = indexIterator.next();
        this.client
                .admin()
                .indices()
                .exists(
                        new IndicesExistsRequest(index),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndicesExistsResponse existsResponse) {
                                if (!existsResponse.isExists()) {
                                    hasEngineResourcesNext(space, indexIterator, listener);
                                    return;
                                }
                                SearchRequest searchRequest = new SearchRequest(index);
                                searchRequest
                                        .source()
                                        .query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()))
                                        .size(1);
                                client.search(
                                        searchRequest,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(SearchResponse response) {
                                                if (response.getHits().getTotalHits().value() > 0) {
                                                    listener.onResponse(true);
                                                } else {
                                                    hasEngineResourcesNext(space, indexIterator, listener);
                                                }
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                log.warn(
                                                        Constants.W_LOG_CHECK_ENGINE_RESOURCES_FAILED,
                                                        space,
                                                        index,
                                                        e.getMessage());
                                                hasEngineResourcesNext(space, indexIterator, listener);
                                            }
                                        });
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.warn(
                                        Constants.W_LOG_CHECK_ENGINE_RESOURCES_FAILED, space, index, e.getMessage());
                                hasEngineResourcesNext(space, indexIterator, listener);
                            }
                        });
    }
}
