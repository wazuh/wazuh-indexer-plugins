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
package com.wazuh.contentmanager.cti.catalog.index;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Semaphore;

import com.wazuh.contentmanager.cti.catalog.model.*;
import com.wazuh.contentmanager.cti.catalog.utils.JsonPatch;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.YamlUtils;

/**
 * Manages the index for CTI content, providing methods for index creation, document indexing,
 * updating, deletion, and bulk operations.
 */
public class ContentIndex {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    /** The first physical suffix used when creating alias-backed indices. */
    public static final String SUFFIX_A = "-a";

    /** The second physical suffix, used as the shadow slot during blue/green swaps. */
    public static final String SUFFIX_B = "-b";

    private final Client client;
    private final PluginSettings pluginSettings;
    private final Semaphore semaphore;

    /**
     * The public alias name (e.g., {@code "wazuh-threatintel-rules"}). All read operations use this
     * name so they transparently resolve through the alias.
     */
    private final String indexName;

    /**
     * The physical index name targeted by write operations (e.g., {@code
     * "wazuh-threatintel-rules-a"}). For normal (non-shadow) instances this is {@code indexName +
     * SUFFIX_A}; for shadow instances it is the alternate suffix.
     */
    private final String physicalName;

    private final String mappingsPath;
    private final ObjectMapper mapper;

    /**
     * Whether this instance targets a shadow physical index during a blue/green swap. Normal
     * instances write through the alias; shadow instances write directly to the physical name because
     * the alias still points at the old live index until the atomic swap completes.
     */
    private final boolean isShadow;

    /**
     * Constructor for existing indices where mapping path isn't immediately required. Reads and
     * writes go through the alias name.
     *
     * @param client The OpenSearch client.
     * @param indexName The public alias name of the index.
     */
    public ContentIndex(Client client, String indexName) {
        this(client, indexName, indexName + SUFFIX_A, null, false);
    }

    /**
     * Constructs a new ContentIndex manager. The physical index defaults to {@code indexName +
     * SUFFIX_A}.
     *
     * @param client The OpenSearch client used to communicate with the cluster.
     * @param indexName The public alias name of the index.
     * @param mappingsPath The classpath resource path to the JSON mapping file.
     */
    public ContentIndex(Client client, String indexName, String mappingsPath) {
        this(client, indexName, indexName + SUFFIX_A, mappingsPath, false);
    }

    /**
     * Constructs a ContentIndex targeting a specific physical index name. Used during blue/green
     * swaps to write into shadow indices.
     *
     * @param client The OpenSearch client.
     * @param indexName The public alias name (used for reads and payload processing).
     * @param physicalName The concrete physical index name (used for writes and index creation).
     * @param mappingsPath The classpath resource path to the JSON mapping file.
     */
    public ContentIndex(Client client, String indexName, String physicalName, String mappingsPath) {
        this(client, indexName, physicalName, mappingsPath, true);
    }

    private ContentIndex(
            Client client, String indexName, String physicalName, String mappingsPath, boolean isShadow) {
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(this.pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
        this.indexName = indexName;
        this.physicalName = physicalName;
        this.mappingsPath = mappingsPath;
        this.isShadow = isShadow;
        this.mapper = new ObjectMapper();
        this.mapper.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    }

    /**
     * Returns the public alias name of the index managed by this instance.
     *
     * @return The alias name.
     */
    public String getIndexName() {
        return this.indexName;
    }

    /**
     * Returns the physical index name targeted by write operations.
     *
     * @return The physical index name (e.g., {@code "wazuh-threatintel-rules-a"}).
     */
    public String getPhysicalName() {
        return this.physicalName;
    }

    /**
     * Returns the index name to use for write operations (create, update, delete, bulk). For normal
     * instances this is the alias name (writes through the alias resolve to the live physical index).
     * For shadow instances (where the alias still points at the old live index) this is the physical
     * name, so writes go directly to the shadow index.
     *
     * @return The index name to target for writes.
     */
    public String getWriteIndex() {
        return this.isShadow ? this.physicalName : this.indexName;
    }

    /**
     * Creates the physical index in OpenSearch with the configured mappings and settings, and assigns
     * the public alias to it.
     *
     * @param listener The listener to notify with the create index response, or null if mappings
     *     could not be read.
     */
    public void createIndex(ActionListener<CreateIndexResponse> listener) {
        if (this.mappingsPath == null) {
            log.error(Constants.E_LOG_CREATE_INDEX_NO_MAPPINGS, this.indexName);
            listener.onResponse(null);
            return;
        }

        Settings.Builder settingsBuilder =
                Settings.builder()
                        .put("index.number_of_replicas", 0)
                        .put(Constants.KEY_INDEX_CODEC, Constants.CODEC_ZSTD);
        if (Constants.INDEX_CVES.equals(this.indexName)) {
            settingsBuilder.put("index.hidden", true);
        }
        Settings settings = settingsBuilder.build();

        String mappings = this.readMappings();
        if (mappings == null) {
            listener.onResponse(null);
            return;
        }

        CreateIndexRequest request =
                new CreateIndexRequest().index(this.physicalName).mapping(mappings).settings(settings);

        this.client
                .admin()
                .indices()
                .create(
                        request,
                        ActionListener.wrap(
                                response -> {
                                    if (response.isAcknowledged()) {
                                        IndicesAliasesRequest aliasRequest =
                                                new IndicesAliasesRequest()
                                                        .addAliasAction(
                                                                IndicesAliasesRequest.AliasActions.add()
                                                                        .index(this.physicalName)
                                                                        .alias(this.indexName)
                                                                        .writeIndex(true));
                                        this.client
                                                .admin()
                                                .indices()
                                                .aliases(
                                                        aliasRequest,
                                                        ActionListener.wrap(
                                                                aliasResponse -> {
                                                                    log.debug(
                                                                            Constants.D_LOG_INDEX_CREATED_WITH_ALIAS,
                                                                            this.physicalName,
                                                                            this.indexName);
                                                                    listener.onResponse(response);
                                                                },
                                                                listener::onFailure));
                                    } else {
                                        listener.onResponse(response);
                                    }
                                },
                                listener::onFailure));
    }

    /**
     * Creates a hidden shadow physical index without an alias. Used during blue/green swaps to
     * prepare the staging slot.
     *
     * @param listener The listener to notify with the create index response.
     */
    public void createShadowIndex(ActionListener<CreateIndexResponse> listener) {
        if (this.mappingsPath == null) {
            log.error(Constants.E_LOG_CREATE_SHADOW_INDEX_NO_MAPPINGS, this.physicalName);
            listener.onResponse(null);
            return;
        }

        Settings settings =
                Settings.builder()
                        .put("index.number_of_replicas", 0)
                        .put("index.hidden", true)
                        .put(Constants.KEY_INDEX_CODEC, Constants.CODEC_ZSTD)
                        .build();

        String mappings = this.readMappings();
        if (mappings == null) {
            listener.onResponse(null);
            return;
        }

        CreateIndexRequest request =
                new CreateIndexRequest().index(this.physicalName).mapping(mappings).settings(settings);

        this.client
                .admin()
                .indices()
                .create(
                        request,
                        ActionListener.wrap(
                                response -> {
                                    if (response.isAcknowledged()) {
                                        log.debug(Constants.D_LOG_SHADOW_INDEX_CREATED, this.physicalName);
                                    }
                                    listener.onResponse(response);
                                },
                                listener::onFailure));
    }

    /**
     * Reads the JSON mappings from the classpath resource.
     *
     * @return The mappings string, or null if the file could not be read.
     */
    private String readMappings() {
        try (InputStream is = this.getClass().getResourceAsStream(this.mappingsPath)) {
            if (is == null) {
                log.error(Constants.E_LOG_MAPPINGS_FILE_NOT_FOUND, this.mappingsPath, this.indexName);
                return null;
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error(Constants.E_LOG_READ_MAPPINGS_FAILED, this.indexName, e.getMessage());
            return null;
        }
    }

    /**
     * Checks if a document with the specified ID exists in the index.
     *
     * @param id The ID of the document to check.
     * @param listener The listener to notify with the existence result.
     */
    public void exists(String id, ActionListener<Boolean> listener) {
        GetRequest getRequest =
                new GetRequest(this.indexName, id)
                        .fetchSourceContext(FetchSourceContext.DO_NOT_FETCH_SOURCE);
        this.client.get(
                getRequest,
                ActionListener.wrap(
                        response -> listener.onResponse(response.isExists()), listener::onFailure));
    }

    /**
     * Retrieves a document by ID and returns it as a Jackson JsonNode.
     *
     * @param id The document ID.
     * @param listener The listener to notify with the document source, or null if not found.
     */
    public void getDocument(String id, ActionListener<JsonNode> listener) {
        this.client.get(
                new GetRequest(this.indexName, id),
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse response) {
                        try {
                            if (response.isExists() && response.getSourceAsString() != null) {
                                listener.onResponse(
                                        ContentIndex.this.mapper.readTree(response.getSourceAsString()));
                            } else {
                                listener.onResponse(null);
                            }
                        } catch (Exception e) {
                            listener.onFailure(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(Constants.E_LOG_GET_DOCUMENT_FAILED, id, indexName, e.getMessage());
                        listener.onResponse(null);
                    }
                });
    }

    /**
     * Indexes a new document or overwrites an existing one.
     *
     * @param id The unique identifier for the document.
     * @param payload The JSON object representing the document content.
     * @param listener The listener to notify with the index response.
     */
    public void create(String id, JsonNode payload, ActionListener<IndexResponse> listener) {
        ObjectNode processedPayload;
        if (payload.isObject()
                && payload.has("document")
                && payload.has("space")
                && payload.has("hash")) {
            processedPayload = payload.deepCopy();
        } else {
            processedPayload = this.processPayload(payload);
        }

        // Ensure floating-point values keep their decimal scale
        if (processedPayload.has("document")) {
            YamlUtils.fixDecimalScale(processedPayload.get("document"));
        }

        IndexRequest request =
                new IndexRequest(this.getWriteIndex())
                        .id(id)
                        .source(processedPayload.toString(), XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        this.client.index(request, listener);
    }

    /**
     * Updates an existing document by applying a list of patch operations.
     *
     * @param id The ID of the document to update.
     * @param operations The list of operations to apply to the document.
     * @param listener The listener to notify on completion.
     */
    public void update(String id, List<Operation> operations, ActionListener<Void> listener) {
        this.update(id, operations, null, listener);
    }

    /**
     * Updates an existing document by applying a list of patch operations and optionally setting the
     * CTI offset.
     *
     * @param id The ID of the document to update.
     * @param operations The list of operations to apply to the document.
     * @param offset The CTI offset value to store on the document, or null to leave unchanged.
     * @param listener The listener to notify on completion.
     */
    public void update(
            String id, List<Operation> operations, Long offset, ActionListener<Void> listener) {
        this.client.get(
                new GetRequest(this.indexName, id),
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse response) {
                        try {
                            if (!response.isExists()) {
                                listener.onFailure(new IOException("Document [" + id + "] not found for update."));
                                return;
                            }

                            ObjectNode currentDoc =
                                    (ObjectNode) ContentIndex.this.mapper.readTree(response.getSourceAsString());

                            if (ContentIndex.this.indexName.equals(Constants.INDEX_CVES)) {
                                currentDoc = (ObjectNode) currentDoc.get(Constants.KEY_DOCUMENT);
                            }

                            for (Operation op : operations) {
                                JsonNode opJson = ContentIndex.this.mapper.valueToTree(op);
                                JsonPatch.applyOperation(currentDoc, opJson);
                            }

                            if (offset != null) {
                                currentDoc.put(Constants.KEY_OFFSET, offset);
                            }

                            ObjectNode processedDoc = ContentIndex.this.processPayload(currentDoc);

                            IndexRequest request =
                                    new IndexRequest(ContentIndex.this.getWriteIndex())
                                            .id(id)
                                            .source(processedDoc.toString(), XContentType.JSON);
                            ContentIndex.this.client.index(
                                    request,
                                    ActionListener.wrap(
                                            indexResponse -> listener.onResponse(null), listener::onFailure));
                        } catch (Exception e) {
                            listener.onFailure(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
    }

    /**
     * Asynchronously deletes a document from the index.
     *
     * @param id The ID of the document to delete.
     */
    public void delete(String id) {
        this.client.delete(
                new DeleteRequest(this.getWriteIndex(), id)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE),
                new ActionListener<>() {
                    @Override
                    public void onResponse(DeleteResponse response) {
                        log.debug(Constants.D_LOG_DELETED_FROM_INDEX, id, ContentIndex.this.indexName);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(Constants.E_LOG_DELETE_DOCUMENT_FAILED, id, e.getMessage());
                    }
                });
    }

    /**
     * Determines the product from the document (logsource.product or logsource.category). Defaults to
     * "linux".
     *
     * @param ruleNode The rule Jackson JsonNode.
     * @return The determined product string.
     */
    public static String extractProduct(JsonNode ruleNode) {
        // TODO: Move this method to a dedicated CTI Resource logic class.
        String product = "linux";
        if (ruleNode.has(Constants.KEY_LOGSOURCE)) {
            JsonNode logsource = ruleNode.get(Constants.KEY_LOGSOURCE);
            if (logsource.has(Constants.KEY_PRODUCT)) {
                product = logsource.get(Constants.KEY_PRODUCT).asText();
            } else if (logsource.has(Constants.KEY_CATEGORY)) {
                product = logsource.get(Constants.KEY_CATEGORY).asText();
            }
        }
        return product;
    }

    /**
     * Searches for a document by a specific field name and value.
     *
     * @param queryBuilder The query to execute.
     * @param listener The listener to notify with the search result, or null if not found.
     */
    public void searchByQuery(QueryBuilder queryBuilder, ActionListener<ObjectNode> listener) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(queryBuilder);
        SearchRequest searchRequest = new SearchRequest(this.indexName).source(searchSourceBuilder);

        this.client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse searchResponse) {
                        try {
                            if (searchResponse == null
                                    || searchResponse.getHits() == null
                                    || searchResponse.getHits().getTotalHits() == null
                                    || searchResponse.getHits().getTotalHits().value() == 0L) {
                                log.debug(
                                        Constants.D_LOG_NO_DOCUMENT_FOUND_QUERY, indexName, queryBuilder.toString());
                                listener.onResponse(null);
                                return;
                            }
                            ArrayNode hitsArray = ContentIndex.this.mapper.createArrayNode();
                            for (SearchHit hit : searchResponse.getHits().getHits()) {
                                ObjectNode hitObject =
                                        (ObjectNode) ContentIndex.this.mapper.readTree(hit.getSourceAsString());
                                hitObject.put(Constants.KEY_ID, hit.getId());
                                hitsArray.add(hitObject);
                            }
                            ObjectNode result = ContentIndex.this.mapper.createObjectNode();
                            result.set(Constants.Q_HITS, hitsArray);
                            result.put("total", searchResponse.getHits().getTotalHits().value());
                            listener.onResponse(result);
                        } catch (Exception e) {
                            listener.onFailure(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(Constants.E_LOG_SEARCH_BY_QUERY_FAILED, indexName, e.getMessage());
                        listener.onResponse(null);
                    }
                });
    }

    /**
     * Executes a bulk request asynchronously.
     *
     * @param bulkRequest The BulkRequest containing multiple index/delete operations.
     */
    public void executeBulk(BulkRequest bulkRequest) {
        try {
            this.semaphore.acquire();
            this.client.bulk(
                    bulkRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(BulkResponse bulkResponse) {
                            ContentIndex.this.semaphore.release();
                            if (bulkResponse.hasFailures()) {
                                log.warn(
                                        Constants.W_LOG_BULK_INDEXING_FAILURES, bulkResponse.buildFailureMessage());
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            ContentIndex.this.semaphore.release();
                            log.error(Constants.E_LOG_BULK_INDEX_OPERATION_FAILED, e.getMessage());
                        }
                    });
        } catch (InterruptedException e) {
            log.error(Constants.E_LOG_SEMAPHORE_INTERRUPTED, e.getMessage());
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Waits until all pending bulk requests have completed. Use this to ensure all async indexing
     * operations are finished.
     *
     * @throws InterruptedException If the thread is interrupted while waiting.
     */
    public void waitForPendingUpdates() throws InterruptedException {
        int permits = this.pluginSettings.getMaximumConcurrentBulks();
        this.semaphore.acquire(permits);
        this.semaphore.release(permits);
    }

    /**
     * Deletes all documents in the index by deleting the physical index and recreating it with the
     * alias.
     *
     * @param listener The listener to notify on completion.
     */
    public void clear(ActionListener<Void> listener) {
        if (this.mappingsPath == null) {
            log.error(Constants.E_LOG_CLEAR_INDEX_NO_MAPPINGS, this.indexName);
            listener.onResponse(null);
            return;
        }
        try {
            this.client
                    .admin()
                    .indices()
                    .exists(
                            new IndicesExistsRequest(this.physicalName),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(
                                        org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse
                                                existsResponse) {
                                    if (existsResponse.isExists()) {
                                        ContentIndex.this
                                                .client
                                                .admin()
                                                .indices()
                                                .delete(
                                                        new DeleteIndexRequest(ContentIndex.this.physicalName),
                                                        ActionListener.wrap(
                                                                deleteResponse -> ContentIndex.this.recreateAfterClear(listener),
                                                                e -> {
                                                                    log.error(
                                                                            Constants.E_LOG_CLEAR_INDEX_FAILED,
                                                                            indexName,
                                                                            e.getMessage());
                                                                    listener.onResponse(null);
                                                                }));
                                    } else {
                                        ContentIndex.this.recreateAfterClear(listener);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.error(Constants.E_LOG_CLEAR_INDEX_FAILED, indexName, e.getMessage());
                                    listener.onResponse(null);
                                }
                            });
        } catch (Exception e) {
            log.error(Constants.E_LOG_CLEAR_INDEX_FAILED, this.indexName, e.getMessage());
            listener.onResponse(null);
        }
    }

    private void recreateAfterClear(ActionListener<Void> listener) {
        this.createIndex(
                ActionListener.wrap(
                        response -> {
                            log.debug(Constants.D_LOG_INDEX_WIPED_RECREATED, this.indexName, this.physicalName);
                            listener.onResponse(null);
                        },
                        e -> {
                            log.error(Constants.E_LOG_CLEAR_INDEX_FAILED, this.indexName, e.getMessage());
                            listener.onResponse(null);
                        }));
    }

    /**
     * Orchestrates the enrichment and sanitization of a payload using Domain Models.
     *
     * @param payload The JSON payload to process.
     * @return A new JsonObject containing the processed payload.
     */
    public ObjectNode processPayload(JsonNode payload) {
        try {
            // Delegate parsing logic to the appropriate Model
            Resource resource;
            switch (this.indexName) {
                case Constants.INDEX_IOCS:
                    Ioc ioc = Ioc.fromPayload(payload);
                    return this.mapper.valueToTree(ioc);
                case Constants.INDEX_DECODERS:
                    resource = Decoder.fromPayload(payload);
                    break;
                case Constants.INDEX_KVDBS:
                    resource = Kvdb.fromPayload(payload);
                    break;
                case Constants.INDEX_FILTERS:
                    resource = Filter.fromPayload(payload);
                    break;
                case Constants.INDEX_POLICIES:
                    resource = Resource.fromPayload(payload);
                    if (payload.has(Constants.KEY_DOCUMENT)) {
                        // Re-parse the document through the Policy model so optional fields
                        // (enabled, index_unclassified_events, index_discarded_events) are
                        // always present in the indexed document, and recompute the document
                        // hash to match the normalized payload.
                        Policy policy = Policy.fromPayload(payload.get(Constants.KEY_DOCUMENT));
                        ObjectNode policyNode = this.mapper.valueToTree(policy);
                        Resource.nestMetadataFields(policyNode);
                        resource.setDocument(policyNode);
                        java.util.Map<String, String> hashMap = new java.util.HashMap<>();
                        hashMap.put(Constants.KEY_SHA256, Resource.computeSha256(policyNode.toString()));
                        resource.setHash(hashMap);
                    }
                    break;
                case Constants.INDEX_CVES:
                    Cve cve = Cve.fromPayload(payload);
                    return this.mapper.valueToTree(cve);
                default:
                    resource = Resource.fromPayload(payload);
                    break;
            }

            return this.mapper.valueToTree(resource);
        } catch (Exception e) {
            log.error(Constants.E_LOG_PROCESS_PAYLOAD_FAILED, e.getMessage(), e);
            return this.mapper.createObjectNode();
        }
    }
}
