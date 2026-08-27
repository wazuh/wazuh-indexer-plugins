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

import com.fasterxml.jackson.core.JsonProcessingException;
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
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.breaker.CircuitBreakingException;
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

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

    private static final int MAX_UPDATE_RETRIES = 3;
    private static final long UPDATE_INITIAL_BACKOFF_MS = 1000;
    private static final long UPDATE_MAX_BACKOFF_MS = 30_000;

    private static final int MAX_BULK_RETRIES = 3;
    private static final long BULK_INITIAL_BACKOFF_MS = 1000;
    private static final long BULK_MAX_BACKOFF_MS = 30_000;

    /** Maximum number of UPDATE offsets to batch into a single MultiGet + BulkRequest. */
    public static final int UPDATE_SUB_BATCH_SIZE = 50;

    /** Describes a single document update: the document ID, patch operations, and CTI offset. */
    public record UpdateTask(String id, List<Operation> operations, long offset) {}

    private final Client client;
    private final PluginSettings pluginSettings;
    private final Semaphore semaphore;

    /**
     * Documents this instance failed to index and gave up on, either because the failure was not
     * retryable or because the retry budget was exhausted. Callers loading a full snapshot must check
     * this before advancing the consumer offset, otherwise the dropped documents are never
     * backfilled.
     */
    private final AtomicLong droppedDocuments = new AtomicLong();

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
    private static final ObjectMapper MAPPER =
            new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

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
     * Creates the index in OpenSearch using the configured mappings and settings.
     *
     * <p>Applies specific settings (replicas=0) and registers an alias if one is defined.
     *
     * @return The response from the create index operation, or null if mappings could not be read.
     * @throws ExecutionException If the client execution fails.
     * @throws InterruptedException If the thread is interrupted while waiting.
     * @throws TimeoutException If the operation exceeds the client timeout setting.
     */
    /**
     * Creates the physical index in OpenSearch with the configured mappings and settings, and assigns
     * the public alias to it.
     *
     * <p>The physical index is created using {@link #physicalName} (e.g., {@code
     * "wazuh-threatintel-rules-a"}) and the alias {@link #indexName} (e.g., {@code
     * "wazuh-threatintel-rules"}) is pointed at it with {@code is_write_index: true}.
     *
     * @return The response from the create index operation, or null if mappings could not be read.
     * @throws ExecutionException If the client execution fails.
     * @throws InterruptedException If the thread is interrupted while waiting.
     * @throws TimeoutException If the operation exceeds the client timeout setting.
     */
    public CreateIndexResponse createIndex()
            throws ExecutionException, InterruptedException, TimeoutException {
        if (this.mappingsPath == null) {
            log.error(Constants.E_LOG_CREATE_INDEX_NO_MAPPINGS, this.indexName);
            return null;
        }

        Settings.Builder settingsBuilder =
                Settings.builder()
                        .put("index.number_of_replicas", 0)
                        .put("index.auto_expand_replicas", "0-1")
                        .put(Constants.KEY_INDEX_CODEC, Constants.CODEC_ZSTD);
        if (Constants.INDEX_CVES.equals(this.indexName)) {
            settingsBuilder.put("index.hidden", true);
        }
        Settings settings = settingsBuilder.build();

        String mappings = this.readMappings();
        if (mappings == null) {
            return null;
        }

        CreateIndexRequest request =
                new CreateIndexRequest().index(this.physicalName).mapping(mappings).settings(settings);

        CreateIndexResponse response =
                this.client
                        .admin()
                        .indices()
                        .create(request)
                        .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

        // Assign the public alias to the newly created physical index.
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
                    .aliases(aliasRequest)
                    .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
            log.debug(Constants.D_LOG_INDEX_CREATED_WITH_ALIAS, this.physicalName, this.indexName);
        }

        return response;
    }

    /**
     * Creates a hidden shadow physical index without an alias. Used during blue/green swaps to
     * prepare the staging slot. The index is hidden so its partial contents are not exposed via
     * {@code _cat/indices}, Dashboards, or wildcard queries during the rebuild window.
     *
     * @return The response from the create index operation, or null if mappings could not be read.
     * @throws ExecutionException If the client execution fails.
     * @throws InterruptedException If the thread is interrupted while waiting.
     * @throws TimeoutException If the operation exceeds the client timeout setting.
     */
    public CreateIndexResponse createShadowIndex()
            throws ExecutionException, InterruptedException, TimeoutException {
        if (this.mappingsPath == null) {
            log.error(Constants.E_LOG_CREATE_SHADOW_INDEX_NO_MAPPINGS, this.physicalName);
            return null;
        }

        Settings settings =
                Settings.builder()
                        .put("index.number_of_replicas", 0)
                        .put("index.auto_expand_replicas", "0-1")
                        .put("index.hidden", true)
                        .put(Constants.KEY_INDEX_CODEC, Constants.CODEC_ZSTD)
                        .build();

        String mappings = this.readMappings();
        if (mappings == null) {
            return null;
        }

        CreateIndexRequest request =
                new CreateIndexRequest().index(this.physicalName).mapping(mappings).settings(settings);

        CreateIndexResponse response =
                this.client
                        .admin()
                        .indices()
                        .create(request)
                        .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

        if (response.isAcknowledged()) {
            log.debug(Constants.D_LOG_SHADOW_INDEX_CREATED, this.physicalName);
        }

        return response;
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
     * @return true if the document exists, false otherwise.
     */
    public boolean exists(String id) {
        return this.client.prepareGet(this.indexName, id).setFetchSource(false).get().isExists();
    }

    /**
     * Retrieves a document by ID and returns it as a Jackson JsonNode.
     *
     * @param id The document ID.
     * @return The document source as JsonNode, or null if not found.
     */
    public JsonNode getDocument(String id) {
        try {
            GetResponse response = this.client.prepareGet(this.indexName, id).get();
            if (response.isExists() && response.getSourceAsString() != null) {
                return MAPPER.readTree(response.getSourceAsString());
            }
        } catch (Exception e) {
            log.error(Constants.E_LOG_GET_DOCUMENT_FAILED, id, this.indexName, e.getMessage());
        }
        return null;
    }

    /**
     * Indexes a new document or overwrites an existing one with {@link
     * WriteRequest.RefreshPolicy#IMMEDIATE}.
     *
     * @param id The unique identifier for the document.
     * @param payload The JSON object representing the document content.
     * @param listener The listener to notify on completion.
     */
    public void create(String id, JsonNode payload, ActionListener<IndexResponse> listener) {
        this.create(id, payload, listener, WriteRequest.RefreshPolicy.IMMEDIATE);
    }

    /**
     * Indexes a new document or overwrites an existing one with the given refresh policy.
     *
     * @param id The unique identifier for the document.
     * @param payload The JSON object representing the document content.
     * @param listener The listener to notify on completion.
     * @param refreshPolicy The refresh policy to apply after indexing.
     */
    public void create(
            String id,
            JsonNode payload,
            ActionListener<IndexResponse> listener,
            WriteRequest.RefreshPolicy refreshPolicy) {
        ObjectNode processedPayload;
        if (payload.isObject()
                && payload.has(Constants.KEY_DOCUMENT)
                && payload.has(Constants.KEY_SPACE)
                && payload.has(Constants.KEY_HASH)) {
            processedPayload = payload.deepCopy();
        } else {
            processedPayload = this.processPayload(payload);
        }

        if (processedPayload.has(Constants.KEY_DOCUMENT)) {
            YamlUtils.fixDecimalScale(processedPayload.get(Constants.KEY_DOCUMENT));
        }

        IndexRequest request =
                new IndexRequest(this.getWriteIndex())
                        .id(id)
                        .source(processedPayload.toString(), XContentType.JSON)
                        .setRefreshPolicy(refreshPolicy);
        this.client.index(request, listener);
    }

    /**
     * Updates an existing document by applying a list of patch operations.
     *
     * @param id The ID of the document to update.
     * @param operations The list of operations to apply to the document.
     * @throws Exception If the document does not exist, or if patching/indexing fails.
     */
    public void update(String id, List<Operation> operations) throws Exception {
        this.update(id, operations, null);
    }

    /**
     * Updates an existing document by applying a list of patch operations and optionally setting the
     * CTI offset.
     *
     * @param id The ID of the document to update.
     * @param operations The list of operations to apply to the document.
     * @param offset The CTI offset value to store on the document, or null to leave unchanged.
     * @throws Exception If the document does not exist, or if patching/indexing fails.
     */
    public void update(String id, List<Operation> operations, Long offset) throws Exception {
        long backoffMs = UPDATE_INITIAL_BACKOFF_MS;

        for (int attempt = 0; ; attempt++) {
            try {
                this.doUpdate(id, operations, offset);
                return;
            } catch (Exception e) {
                if (attempt < MAX_UPDATE_RETRIES && isCircuitBreakerException(e)) {
                    log.warn(
                            "Circuit breaker tripped during update of [{}], retry {}/{} in {}ms",
                            id,
                            attempt + 1,
                            MAX_UPDATE_RETRIES,
                            backoffMs);
                    Thread.sleep(backoffMs);
                    backoffMs = Math.min(backoffMs * 2, UPDATE_MAX_BACKOFF_MS);
                } else {
                    throw e;
                }
            }
        }
    }

    private void doUpdate(String id, List<Operation> operations, Long offset) throws Exception {
        // 1. Fetch, excluding the derived yaml field to reduce allocation
        FetchSourceContext excludeYaml =
                new FetchSourceContext(true, new String[0], new String[] {Constants.KEY_YAML});
        GetResponse response =
                this.client
                        .get(new GetRequest(this.indexName, id).fetchSourceContext(excludeYaml))
                        .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        if (!response.isExists()) {
            throw new IOException("Document [" + id + "] not found for update.");
        }

        // 2. Patch
        ObjectNode currentDoc = (ObjectNode) MAPPER.readTree(response.getSourceAsString());

        // Resources from the VD feed do not contain a "document" object, so we need to patch the root
        // document instead of the "document" node.
        if (this.indexName.equals(Constants.INDEX_CVES)) {
            currentDoc = (ObjectNode) currentDoc.get(Constants.KEY_DOCUMENT);
            if (currentDoc == null) {
                throw new IOException(
                        "Document [" + id + "] is missing the '" + Constants.KEY_DOCUMENT + "' field.");
            }
        }

        for (Operation op : operations) {
            JsonNode opJson = MAPPER.valueToTree(op);
            JsonPatch.applyOperation(currentDoc, opJson);
        }

        // 2.5. Inject offset if provided
        if (offset != null) {
            currentDoc.put(Constants.KEY_OFFSET, offset);
        }

        // 3. Process
        String processedJson = this.processPayloadToString(currentDoc);

        // 4. Index
        IndexRequest request =
                new IndexRequest(this.getWriteIndex()).id(id).source(processedJson, XContentType.JSON);
        this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Applies a batch of update tasks using a single MultiGet + BulkRequest round-trip pair.
     * Documents whose stored offset already matches the target offset are skipped (idempotency guard
     * for partial-failure retries).
     *
     * @param tasks The update tasks to apply. Must not be empty.
     * @return The offset of the last successfully applied task.
     * @throws Exception If fetching or indexing fails.
     */
    public long batchUpdate(List<UpdateTask> tasks) throws Exception {
        long timeout = this.pluginSettings.getClientTimeout();
        long maxBytes = this.pluginSettings.getMaxBulkBytes();

        // 1. MultiGet all documents, excluding the derived yaml field to reduce allocation
        FetchSourceContext excludeYaml =
                new FetchSourceContext(true, new String[0], new String[] {Constants.KEY_YAML});
        MultiGetRequest mgetRequest = new MultiGetRequest();
        for (UpdateTask task : tasks) {
            mgetRequest.add(
                    new MultiGetRequest.Item(this.indexName, task.id()).fetchSourceContext(excludeYaml));
        }
        MultiGetResponse mgetResponse =
                this.client.multiGet(mgetRequest).get(timeout, TimeUnit.SECONDS);
        MultiGetItemResponse[] responses = mgetResponse.getResponses();

        // 2. Stream: patch each document and flush when size limit is reached
        BulkRequest bulkRequest = new BulkRequest();
        boolean isCve = this.indexName.equals(Constants.INDEX_CVES);

        for (int i = 0; i < tasks.size(); i++) {
            UpdateTask task = tasks.get(i);
            MultiGetItemResponse item = responses[i];

            if (item.isFailed()) {
                throw new IOException(
                        "MultiGet failed for document [" + task.id() + "]: " + item.getFailure().getMessage());
            }
            GetResponse getResp = item.getResponse();
            if (!getResp.isExists()) {
                throw new IOException("Document [" + task.id() + "] not found for update.");
            }

            ObjectNode currentDoc = (ObjectNode) MAPPER.readTree(getResp.getSourceAsString());

            // Idempotency guard: skip if already at this offset
            if (currentDoc.has(Constants.KEY_OFFSET)
                    && currentDoc.get(Constants.KEY_OFFSET).asLong() == task.offset()) {
                continue;
            }

            ObjectNode patchTarget =
                    isCve ? (ObjectNode) currentDoc.get(Constants.KEY_DOCUMENT) : currentDoc;
            if (patchTarget == null) {
                throw new IOException(
                        "Document [" + task.id() + "] is missing the '" + Constants.KEY_DOCUMENT + "' field.");
            }

            for (Operation op : task.operations()) {
                JsonNode opJson = MAPPER.valueToTree(op);
                JsonPatch.applyOperation(patchTarget, opJson);
            }
            patchTarget.put(Constants.KEY_OFFSET, task.offset());

            String processedJson = this.processPayloadToString(patchTarget);
            bulkRequest.add(
                    new IndexRequest(this.getWriteIndex())
                            .id(task.id())
                            .source(processedJson, XContentType.JSON));

            if (bulkRequest.estimatedSizeInBytes() >= maxBytes) {
                this.executeBulkUpdate(bulkRequest, timeout);
                bulkRequest = new BulkRequest();
            }
        }

        if (bulkRequest.numberOfActions() > 0) {
            this.executeBulkUpdate(bulkRequest, timeout);
        }

        return tasks.get(tasks.size() - 1).offset();
    }

    private void executeBulkUpdate(BulkRequest bulkRequest, long timeout) throws Exception {
        BulkResponse bulkResponse = this.client.bulk(bulkRequest).get(timeout, TimeUnit.SECONDS);
        if (bulkResponse.hasFailures()) {
            for (BulkItemResponse item : bulkResponse.getItems()) {
                if (item.isFailed()) {
                    throw new IOException(
                            "Bulk update failed for document ["
                                    + item.getId()
                                    + "]: "
                                    + item.getFailureMessage());
                }
            }
        }
    }

    /**
     * Processes a payload and returns an IndexRequest ready to be added to a BulkRequest.
     *
     * @param id The document ID.
     * @param payload The JSON payload to process and index.
     * @param refreshPolicy The refresh policy for the request.
     * @return An IndexRequest with the processed payload.
     */
    public IndexRequest prepareCreateRequest(
            String id, JsonNode payload, WriteRequest.RefreshPolicy refreshPolicy) {
        ObjectNode processedPayload;
        if (payload.isObject()
                && payload.has(Constants.KEY_DOCUMENT)
                && payload.has(Constants.KEY_SPACE)
                && payload.has(Constants.KEY_HASH)) {
            processedPayload = payload.deepCopy();
        } else {
            processedPayload = this.processPayload(payload);
        }

        if (processedPayload.has(Constants.KEY_DOCUMENT)) {
            YamlUtils.fixDecimalScale(processedPayload.get(Constants.KEY_DOCUMENT));
        }

        return new IndexRequest(this.getWriteIndex())
                .id(id)
                .source(processedPayload.toString(), XContentType.JSON)
                .setRefreshPolicy(refreshPolicy);
    }

    /**
     * Asynchronously deletes a document from the index.
     *
     * @param id The ID of the document to delete.
     */
    public void delete(String id) {
        this.client.delete(
                new DeleteRequest(this.getWriteIndex(), id)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.NONE),
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
     * Searches for documents by a query.
     *
     * @param queryBuilder The query to execute.
     * @param listener The listener to notify with the results, or null if none found.
     */
    public void searchByQuery(QueryBuilder queryBuilder, ActionListener<ObjectNode> listener) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(queryBuilder);
        SearchRequest searchRequest = new SearchRequest(this.indexName).source(searchSourceBuilder);

        this.client.search(
                searchRequest,
                ActionListener.wrap(
                        searchResponse -> {
                            if (searchResponse == null
                                    || searchResponse.getHits() == null
                                    || searchResponse.getHits().getTotalHits() == null
                                    || searchResponse.getHits().getTotalHits().value() == 0L) {
                                log.debug(
                                        Constants.D_LOG_NO_DOCUMENT_FOUND_QUERY,
                                        this.indexName,
                                        queryBuilder.toString());
                                listener.onResponse(null);
                                return;
                            }
                            try {
                                ArrayNode hitsArray = MAPPER.createArrayNode();
                                for (SearchHit hit : searchResponse.getHits().getHits()) {
                                    ObjectNode hitObject = (ObjectNode) MAPPER.readTree(hit.getSourceAsString());
                                    hitObject.put(Constants.KEY_ID, hit.getId());
                                    hitsArray.add(hitObject);
                                }
                                ObjectNode result = MAPPER.createObjectNode();
                                result.set(Constants.Q_HITS, hitsArray);
                                result.put("total", searchResponse.getHits().getTotalHits().value());
                                listener.onResponse(result);
                            } catch (IOException e) {
                                listener.onFailure(e);
                            }
                        },
                        listener::onFailure));
    }

    /**
     * Executes a bulk request asynchronously, retrying the items the cluster sheds under load.
     *
     * <p>The indexer is deliberately configured to shed writes rather than exhaust the heap (see
     * {@code indices.breaker.total.limit} in {@code opensearch.prod.yml}), so a rejected bulk is an
     * expected, transient outcome that the client is responsible for re-submitting. Only the failed
     * items are retried, with exponential backoff, up to {@link #MAX_BULK_RETRIES} attempts.
     *
     * <p>Items that fail for a non-retryable reason, and items still failing once the retry budget is
     * exhausted, are counted in {@link #getDroppedDocuments()} so callers can avoid committing
     * progress over an incomplete load.
     *
     * <p>The concurrency permit is held for the whole retry chain, so {@link
     * #waitForPendingUpdates()} also waits for outstanding retries.
     *
     * @param bulkRequest The BulkRequest containing multiple index/delete operations.
     */
    public void executeBulk(BulkRequest bulkRequest) {
        try {
            this.semaphore.acquire();
        } catch (InterruptedException e) {
            log.error(Constants.E_LOG_SEMAPHORE_INTERRUPTED, e.getMessage());
            Thread.currentThread().interrupt();
            return;
        }
        this.submitBulk(bulkRequest, 0, BULK_INITIAL_BACKOFF_MS);
    }

    /**
     * Submits one attempt of a bulk request. Releases the concurrency permit acquired by {@link
     * #executeBulk(BulkRequest)} once the request settles for good; a scheduled retry keeps holding
     * it.
     *
     * @param bulkRequest The operations to submit on this attempt.
     * @param attempt The zero-based attempt number.
     * @param backoffMs The delay to apply before the next attempt, if one is needed.
     */
    private void submitBulk(BulkRequest bulkRequest, int attempt, long backoffMs) {
        this.client.bulk(
                bulkRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(BulkResponse bulkResponse) {
                        if (!bulkResponse.hasFailures()) {
                            ContentIndex.this.semaphore.release();
                            return;
                        }

                        BulkRequest retryRequest = new BulkRequest();
                        int permanent = 0;
                        String lastPermanentFailure = null;
                        String lastRetryableFailure = null;

                        for (BulkItemResponse item : bulkResponse.getItems()) {
                            if (!item.isFailed()) {
                                continue;
                            }
                            BulkItemResponse.Failure failure = item.getFailure();
                            if (isRetryable(failure)) {
                                retryRequest.add(bulkRequest.requests().get(item.getItemId()));
                                lastRetryableFailure = item.getFailureMessage();
                            } else {
                                permanent++;
                                lastPermanentFailure = item.getFailureMessage();
                            }
                        }

                        if (permanent > 0) {
                            ContentIndex.this.droppedDocuments.addAndGet(permanent);
                            log.error(Constants.E_LOG_BULK_ITEMS_NOT_RETRYABLE, permanent, lastPermanentFailure);
                        }

                        if (retryRequest.numberOfActions() == 0) {
                            ContentIndex.this.semaphore.release();
                            return;
                        }
                        ContentIndex.this.retryOrDrop(retryRequest, attempt, backoffMs, lastRetryableFailure);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        if (isRetryable(e)) {
                            ContentIndex.this.retryOrDrop(bulkRequest, attempt, backoffMs, e.getMessage());
                            return;
                        }
                        ContentIndex.this.droppedDocuments.addAndGet(bulkRequest.numberOfActions());
                        log.error(Constants.E_LOG_BULK_INDEX_OPERATION_FAILED, e.getMessage());
                        ContentIndex.this.semaphore.release();
                    }
                });
    }

    /**
     * Schedules another attempt for the shed operations, or gives up and counts them as dropped once
     * the retry budget is exhausted. Releases the concurrency permit on every terminal path.
     *
     * @param retryRequest The operations still pending.
     * @param attempt The zero-based attempt number that just failed.
     * @param backoffMs The delay to apply before this retry.
     * @param failureMessage The failure reported by the last attempt, for logging.
     */
    private void retryOrDrop(
            BulkRequest retryRequest, int attempt, long backoffMs, String failureMessage) {
        int pending = retryRequest.numberOfActions();

        if (attempt >= MAX_BULK_RETRIES) {
            this.droppedDocuments.addAndGet(pending);
            log.error(Constants.E_LOG_BULK_RETRIES_EXHAUSTED, pending, MAX_BULK_RETRIES, failureMessage);
            this.semaphore.release();
            return;
        }

        log.warn(
                Constants.W_LOG_BULK_RETRY_SCHEDULED, pending, attempt + 1, MAX_BULK_RETRIES, backoffMs);

        long nextBackoffMs = Math.min(backoffMs * 2, BULK_MAX_BACKOFF_MS);
        try {
            this.client
                    .threadPool()
                    .schedule(
                            () -> this.submitBulk(retryRequest, attempt + 1, nextBackoffMs),
                            TimeValue.timeValueMillis(backoffMs),
                            ThreadPool.Names.GENERIC);
        } catch (Exception e) {
            // The node is shutting down, or the scheduler refused the task: the permit must not leak.
            this.droppedDocuments.addAndGet(pending);
            log.error(Constants.E_LOG_BULK_RETRY_SCHEDULE_FAILED, pending, e.getMessage());
            this.semaphore.release();
        }
    }

    /**
     * Returns the number of documents this instance failed to index and gave up on since the last
     * {@link #resetDroppedDocuments()}.
     *
     * @return The dropped document count.
     */
    public long getDroppedDocuments() {
        return this.droppedDocuments.get();
    }

    /** Resets the dropped document counter. Call before starting a full snapshot load. */
    public void resetDroppedDocuments() {
        this.droppedDocuments.set(0);
    }

    /** Returns true if any cause in the chain is an instance of the given type. */
    private static boolean hasCause(Throwable throwable, Class<? extends Throwable> type) {
        Throwable cause = throwable;
        while (cause != null) {
            if (type.isInstance(cause)) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private static boolean isCircuitBreakerException(Exception e) {
        return hasCause(e, CircuitBreakingException.class);
    }

    /**
     * Whether a failure is the cluster shedding load rather than rejecting the document itself.
     * Circuit breaker trips and thread pool / indexing pressure rejections are transient and clear on
     * their own, so the operation is worth re-submitting.
     */
    private static boolean isRetryable(Exception e) {
        return hasCause(e, CircuitBreakingException.class)
                || hasCause(e, OpenSearchRejectedExecutionException.class);
    }

    /** Per-item variant of {@link #isRetryable(Exception)}, which also honours the REST status. */
    private static boolean isRetryable(BulkItemResponse.Failure failure) {
        RestStatus status = failure.getStatus();
        if (status == RestStatus.TOO_MANY_REQUESTS || status == RestStatus.SERVICE_UNAVAILABLE) {
            return true;
        }
        return isRetryable(failure.getCause());
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
     */
    public void clear() {
        if (this.mappingsPath == null) {
            log.error(Constants.E_LOG_CLEAR_INDEX_NO_MAPPINGS, this.indexName);
            return;
        }
        try {
            boolean exists =
                    this.client.admin().indices().prepareExists(this.physicalName).get().isExists();
            if (exists) {
                this.client.admin().indices().prepareDelete(this.physicalName).get();
            }
            this.createIndex();
            log.debug(Constants.D_LOG_INDEX_WIPED_RECREATED, this.indexName, this.physicalName);
        } catch (Exception e) {
            log.error(Constants.E_LOG_CLEAR_INDEX_FAILED, this.indexName, e.getMessage());
        }
    }

    /**
     * Flushes the index, committing the translog to Lucene and triggering segment merges. Use between
     * batches during long-running ingestion to free heap held by translog buffers and small segments.
     */
    public void flush() {
        try {
            this.client.admin().indices().prepareFlush(this.indexName).get();
        } catch (Exception e) {
            log.warn("Failed to flush index [{}]: {}", this.indexName, e.getMessage());
        }
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
                    return MAPPER.valueToTree(ioc);
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
                        ObjectNode policyNode = MAPPER.valueToTree(policy);
                        Resource.nestMetadataFields(policyNode);
                        resource.setDocument(policyNode);
                        java.util.Map<String, String> hashMap = new java.util.HashMap<>();
                        hashMap.put(Constants.KEY_SHA256, Resource.computeSha256(policyNode.toString()));
                        resource.setHash(hashMap);
                    }
                    break;
                case Constants.INDEX_CVES:
                    Cve cve = Cve.fromPayload(payload);
                    return MAPPER.valueToTree(cve);
                default:
                    resource = Resource.fromPayload(payload);
                    break;
            }

            return MAPPER.valueToTree(resource);
        } catch (Exception e) {
            log.error(Constants.E_LOG_PROCESS_PAYLOAD_FAILED, e.getMessage(), e);
            return MAPPER.createObjectNode();
        }
    }

    /**
     * Same transformation as {@link #processPayload} but serializes directly to a JSON string,
     * avoiding the intermediate {@link ObjectNode} tree allocation.
     *
     * @param payload The JSON payload to process.
     * @return The processed payload as a JSON string, or an empty JSON object on failure.
     */
    public String processPayloadToString(JsonNode payload) {
        try {
            Resource resource;
            switch (this.indexName) {
                case Constants.INDEX_IOCS:
                    Ioc ioc = Ioc.fromPayload(payload);
                    return MAPPER.writeValueAsString(ioc);
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
                        Policy policy = Policy.fromPayload(payload.get(Constants.KEY_DOCUMENT));
                        ObjectNode policyNode = MAPPER.valueToTree(policy);
                        Resource.nestMetadataFields(policyNode);
                        resource.setDocument(policyNode);
                        java.util.Map<String, String> hashMap = new java.util.HashMap<>();
                        hashMap.put(Constants.KEY_SHA256, Resource.computeSha256(policyNode.toString()));
                        resource.setHash(hashMap);
                    }
                    break;
                case Constants.INDEX_CVES:
                    Cve cve = Cve.fromPayload(payload);
                    return MAPPER.writeValueAsString(cve);
                default:
                    resource = Resource.fromPayload(payload);
                    break;
            }

            return MAPPER.writeValueAsString(resource);
        } catch (JsonProcessingException e) {
            log.error(Constants.E_LOG_PROCESS_PAYLOAD_FAILED, e.getMessage(), e);
            return "{}";
        } catch (Exception e) {
            log.error(Constants.E_LOG_PROCESS_PAYLOAD_FAILED, e.getMessage(), e);
            return "{}";
        }
    }
}
