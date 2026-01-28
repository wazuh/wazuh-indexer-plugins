/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
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
import com.wazuh.contentmanager.cti.catalog.model.Operation;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.utils.JsonPatch;
import com.wazuh.contentmanager.settings.PluginSettings;

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

    private final ObjectMapper jsonMapper;

    private static final String JSON_TYPE_KEY = "type";
    private static final String JSON_DECODER_KEY = "decoder";

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
        this.jsonMapper = new ObjectMapper();
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
     * Indexes a new document or overwrites an existing one.
     *
     * <p>The payload is pre-processed (sanitized and enriched) before being indexed.
     *
     * @param id The unique identifier for the document.
     * @param payload The JSON object representing the document content.
     * @throws IOException If the indexing operation fails.
     */
    public void create(String id, JsonObject payload) throws IOException {
        JsonObject processedPayload = this.processPayload(payload);
        IndexRequest request =
                new IndexRequest(this.indexName)
                        .id(id)
                        .source(processedPayload.toString(), XContentType.JSON);

        try {
            this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        } catch (Exception e) {
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
     * @throws IOException If the indexing operation fails.
     */
    public void create(String id, JsonNode payload) throws IOException {
        // Convert Jackson JsonNode to Gson JsonObject for compatibility
        JsonObject gsonPayload = JsonParser.parseString(payload.toString()).getAsJsonObject();
        this.create(id, gsonPayload);
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
                new DeleteRequest(this.indexName, id),
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
            if (searchResponse.getHits().getTotalHits() == null
                    || searchResponse.getHits().getTotalHits().value() == 0L) {
                log.debug(
                        "No document found in [{}] with query {}", this.indexName, queryBuilder.toString());
                return null;
            }
            // Parse all hits and return in JsonObject format
            return JsonParser.parseString(searchResponse.getHits().toString()).getAsJsonObject();
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
            Resource resource;

            // 1. Delegate parsing logic to the appropriate Model
            if (payload.has(JSON_TYPE_KEY)
                    && JSON_DECODER_KEY.equalsIgnoreCase(payload.get(JSON_TYPE_KEY).getAsString())) {
                resource = Decoder.fromPayload(payload);
            } else {
                resource = Resource.fromPayload(payload);
            }

            // 2. Convert Model back to JsonObject for OpenSearch indexing
            String jsonString = this.jsonMapper.writeValueAsString(resource);
            return JsonParser.parseString(jsonString).getAsJsonObject();

        } catch (IOException e) {
            log.error("Failed to process payload via models: {}", e.getMessage(), e);
            return new JsonObject();
        }
    }
}
