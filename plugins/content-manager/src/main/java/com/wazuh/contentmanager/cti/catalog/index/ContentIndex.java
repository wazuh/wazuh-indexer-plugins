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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
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
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.model.Decoder;
import com.wazuh.contentmanager.cti.catalog.model.Ioc;
import com.wazuh.contentmanager.cti.catalog.model.Operation;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.cti.catalog.utils.JsonPatch;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Manages the index for CTI content, providing methods for index creation, document indexing,
 * updating, deletion, and bulk operations.
 */
public class ContentIndex {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    private final Client client;
    private final PluginSettings pluginSettings;
    private final Semaphore semaphore;
    private final String indexName;
    private final String mappingsPath;
    private final String alias;

    private final ObjectMapper mapper;

    /**
     * Constructor for existing indices where mapping path isn't immediately required.
     *
     * @param client The OpenSearch client.
     * @param indexName The name of the index.
     */
    public ContentIndex(Client client, String indexName) {
        this(client, indexName, null, null);
    }

    /**
     * Constructs a new ContentIndex manager.
     *
     * @param client The OpenSearch client used to communicate with the cluster.
     * @param indexName The name of the index to manage.
     * @param mappingsPath The classpath resource path to the JSON mapping file.
     */
    public ContentIndex(Client client, String indexName, String mappingsPath) {
        this(client, indexName, mappingsPath, null);
    }

    /**
     * Constructs a new ContentIndex manager with an alias.
     *
     * @param client The OpenSearch client used to communicate with the cluster.
     * @param indexName The name of the index to manage.
     * @param mappingsPath The classpath resource path to the JSON mapping file.
     * @param alias The alias to associate with the index (can be null).
     */
    public ContentIndex(Client client, String indexName, String mappingsPath, String alias) {
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(this.pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
        this.indexName = indexName;
        this.mappingsPath = mappingsPath;
        this.alias = alias;
        this.mapper = new ObjectMapper();
    }

    /**
     * Returns the name of the index managed by this instance.
     *
     * @return The index name.
     */
    public String getIndexName() {
        return this.indexName;
    }

    /**
     * Creates the index in OpenSearch using the configured mappings and settings.
     *
     * <p>Applies specific settings (hidden=true, replicas=0) and registers an alias if one is
     * defined.
     *
     * @return The response from the create index operation, or null if mappings could not be read.
     * @throws ExecutionException If the client execution fails.
     * @throws InterruptedException If the thread is interrupted while waiting.
     * @throws TimeoutException If the operation exceeds the client timeout setting.
     */
    public CreateIndexResponse createIndex()
            throws ExecutionException, InterruptedException, TimeoutException {
        if (this.mappingsPath == null) {
            log.error("Cannot create index [{}]: Mappings path not provided.", this.indexName);
            return null;
        }

        Settings settings =
                Settings.builder().put("index.number_of_replicas", 0).put("hidden", true).build();

        String mappings;
        try (InputStream is = this.getClass().getResourceAsStream(this.mappingsPath)) {
            if (is == null) {
                log.error(
                        "Could not find mappings file [{}] for index [{}]", this.mappingsPath, this.indexName);
                return null;
            }
            mappings = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("Could not read mappings for index [{}]: {}", this.indexName, e.getMessage());
            return null;
        }

        CreateIndexRequest request =
                new CreateIndexRequest().index(this.indexName).mapping(mappings).settings(settings);

        if (this.alias != null && !this.alias.isEmpty()) {
            request.alias(new Alias(this.alias));
        }

        return this.client
                .admin()
                .indices()
                .create(request)
                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
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
                return this.mapper.readTree(response.getSourceAsString());
            }
        } catch (Exception e) {
            log.error("Error retrieving document [{}] from [{}]: {}", id, this.indexName, e.getMessage());
        }
        return null;
    }

    /**
     * Indexes a raw CTI document. This method handles: 1. Wrapping the raw content in the "document"
     * field. 2. Calculating the SHA-256 hash. 3. Adding the "space" metadata. 4. Indexing into
     * OpenSearch.
     *
     * @param id The ID of the document.
     * @param rawContent The content of the rule/decoder/etc. (Jackson JsonNode).
     * @param spaceName The space name (e.g., "custom").
     * @throws IOException If serialization or indexing fails.
     */
    public void indexCtiContent(String id, JsonNode rawContent, String spaceName) throws IOException {
        // TODO: Move this method to a dedicated CTI Resource logic class.
        ObjectNode ctiWrapper = this.mapper.createObjectNode();

        // 1. Wrap document
        ctiWrapper.set(Constants.KEY_DOCUMENT, rawContent);

        // 2. Calculate Hash
        String hash = HashCalculator.sha256(rawContent.toString());
        ObjectNode hashNode = this.mapper.createObjectNode();
        hashNode.put(Constants.KEY_SHA256, hash);
        ctiWrapper.set(Constants.KEY_HASH, hashNode);

        // 3. Set Space
        ObjectNode spaceNode = this.mapper.createObjectNode();
        spaceNode.put(Constants.KEY_NAME, spaceName);
        ctiWrapper.set(Constants.KEY_SPACE, spaceNode);

        // 4. Index
        IndexRequest indexRequest =
                new IndexRequest(this.indexName)
                        .id(id)
                        .source(ctiWrapper.toString(), XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        this.client.index(indexRequest).actionGet();
    }

    /**
     * Indexes a new document or overwrites an existing one.
     *
     * <p>The payload is pre-processed (sanitized and enriched) before being indexed.
     *
     * @param id The unique identifier for the document.
     * @param payload The JSON object representing the document content.
     * @return The IndexResponse object with the result of the indexing operation.
     * @throws IOException If the indexing operation fails.
     */
    public IndexResponse create(String id, JsonObject payload) throws IOException {
        JsonObject processedPayload = this.processPayload(payload);
        IndexRequest request =
                new IndexRequest(this.indexName)
                        .id(id)
                        .source(processedPayload.toString(), XContentType.JSON);
        try {
            return this.client
                    .index(request)
                    .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Failed to index document [{}]: {}", id, e.getMessage());
            throw new IOException(e);
        }
    }

    /**
     * Indexes a new document or overwrites an existing one using Jackson JsonNode.
     *
     * <p>The payload is pre-processed (sanitized and enriched) before being indexed. This method
     * accepts a Jackson JsonNode and converts it to Gson JsonObject for compatibility with existing
     * processing logic.
     *
     * @param id The unique identifier for the document.
     * @param payload The Jackson JsonNode representing the document content.
     * @return The IndexResponse object with the result of the indexing operation.
     * @throws IOException If the indexing operation fails.
     */
    public IndexResponse create(String id, JsonNode payload) throws IOException {
        // Convert Jackson JsonNode to Gson JsonObject for compatibility
        JsonObject gsonPayload = JsonParser.parseString(payload.toString()).getAsJsonObject();
        return this.create(id, gsonPayload);
    }

    /**
     * Updates an existing document by applying a list of patch operations.
     *
     * @param id The ID of the document to update.
     * @param operations The list of operations to apply to the document.
     * @throws Exception If the document does not exist, or if patching/indexing fails.
     */
    public void update(String id, List<Operation> operations) throws Exception {
        // 1. Fetch
        GetResponse response =
                this.client
                        .get(new GetRequest(this.indexName, id))
                        .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        if (!response.isExists()) {
            throw new IOException("Document [" + id + "] not found for update.");
        }

        // 2. Patch
        JsonObject currentDoc = JsonParser.parseString(response.getSourceAsString()).getAsJsonObject();
        for (Operation op : operations) {
            XContentBuilder builder = XContentFactory.jsonBuilder();
            op.toXContent(builder, ToXContent.EMPTY_PARAMS);
            JsonObject opJson = JsonParser.parseString(builder.toString()).getAsJsonObject();
            JsonPatch.applyOperation(currentDoc, opJson);
        }

        // 3. Process
        JsonObject processedDoc = this.processPayload(currentDoc);

        // 4. Index
        IndexRequest request =
                new IndexRequest(this.indexName).id(id).source(processedDoc.toString(), XContentType.JSON);
        this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Asynchronously deletes a document from the index.
     *
     * @param id The ID of the document to delete.
     */
    public void delete(String id) {
        this.client.delete(
                new DeleteRequest(this.indexName, id)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE),
                new ActionListener<>() {
                    @Override
                    public void onResponse(DeleteResponse response) {
                        log.debug("Deleted {} from {}", id, ContentIndex.this.indexName);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to delete {}: {}", id, e.getMessage());
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
     * Determines the product from the document (logsource.product or logsource.category). Defaults to
     * "linux".
     *
     * @param ruleNode The rule Gson JsonObject.
     * @return The determined product string.
     */
    // TODO: Study if it can be used JsonNode or JsonObject in all the files so we can avoid having
    // this two methods
    public static String extractProduct(JsonObject ruleNode) {
        String product = "linux";
        if (ruleNode.has(Constants.KEY_LOGSOURCE)) {
            JsonObject logsource = ruleNode.getAsJsonObject(Constants.KEY_LOGSOURCE);
            if (logsource.has(Constants.KEY_PRODUCT)) {
                product = logsource.get(Constants.KEY_PRODUCT).getAsString();
            } else if (logsource.has(Constants.KEY_CATEGORY)) {
                product = logsource.get(Constants.KEY_CATEGORY).getAsString();
            }
        }
        return product;
    }

    /**
     * Searches for a document by a specific field name and value.
     *
     * @param queryBuilder The query to execute.
     * @return A JsonObject representing the found document, or null if not found or on
     */
    public JsonObject searchByQuery(QueryBuilder queryBuilder) {
        try {
            // Create search request
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(queryBuilder);
            SearchRequest searchRequest = new SearchRequest(this.indexName).source(searchSourceBuilder);

            // Execute search synchronously
            SearchResponse searchResponse =
                    this.client
                            .search(searchRequest)
                            .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

            // Check if we have results
            if (searchResponse == null
                    || searchResponse.getHits() == null
                    || searchResponse.getHits().getTotalHits() == null
                    || searchResponse.getHits().getTotalHits().value() == 0L) {
                log.debug(
                        "No document found in [{}] with query {}", this.indexName, queryBuilder.toString());
                return null;
            }
            // Parse all hits and return in JsonObject format
            JsonArray hitsArray = new JsonArray();
            for (SearchHit hit : searchResponse.getHits().getHits()) {
                JsonObject hitObject = JsonParser.parseString(hit.getSourceAsString()).getAsJsonObject();
                hitObject.addProperty(Constants.KEY_ID, hit.getId());
                hitsArray.add(hitObject);
            }
            JsonObject result = new JsonObject();
            result.add(Constants.Q_HITS, hitsArray);
            result.addProperty("total", searchResponse.getHits().getTotalHits().value());
            return result;
        } catch (JsonSyntaxException | InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Search by query failed in [{}]: {}", this.indexName, e.getMessage());
            return null;
        }
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
                                        "Bulk indexing finished with failures: {}", bulkResponse.buildFailureMessage());
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            ContentIndex.this.semaphore.release();
                            log.error("Bulk index operation failed: {}", e.getMessage());
                        }
                    });
        } catch (InterruptedException e) {
            log.error("Interrupted while waiting for semaphore: {}", e.getMessage());
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

    /** Deletes all documents in the index using a "match_all" query. */
    public void clear() {
        try {
            DeleteByQueryRequestBuilder deleteByQuery =
                    new DeleteByQueryRequestBuilder(this.client, DeleteByQueryAction.INSTANCE);
            deleteByQuery.source(this.indexName).filter(QueryBuilders.matchAllQuery());
            BulkByScrollResponse response = deleteByQuery.get();
            log.debug("[{}] wiped. {} documents removed", this.indexName, response.getDeleted());
        } catch (OpenSearchTimeoutException e) {
            log.error("[{}] delete query timed out: {}", this.indexName, e.getMessage());
        }
    }

    /**
     * Orchestrates the enrichment and sanitization of a payload using Domain Models.
     *
     * @param payload The JSON payload to process.
     * @return A new JsonObject containing the processed payload.
     */
    public JsonObject processPayload(JsonObject payload) {
        try {
            // Preserve the type field before processing
            String type =
                    payload.has(Constants.KEY_TYPE) ? payload.get(Constants.KEY_TYPE).getAsString() : null;

            Resource resource;
            // 1. Delegate parsing logic to the appropriate Model
            if (Constants.KEY_DECODER.equalsIgnoreCase(type)) {
                resource = Decoder.fromPayload(payload);
            } else if (payload.has("enrichments")) {
                resource = Ioc.fromPayload(payload);
            } else {
                resource = Resource.fromPayload(payload);
            }

            // 2. Convert Model back to JsonObject for OpenSearch indexing
            String jsonString = this.mapper.writeValueAsString(resource);
            JsonObject result = JsonParser.parseString(jsonString).getAsJsonObject();

            // 3. Re-add the type field to the result
            if (type != null) {
                result.addProperty(Constants.KEY_TYPE, type);
            }

            return result;
        } catch (IOException e) {
            log.error("Failed to process payload via models: {}", e.getMessage(), e);
            return new JsonObject();
        }
    }
}
