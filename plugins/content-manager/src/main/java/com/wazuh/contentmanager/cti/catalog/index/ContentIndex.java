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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.settings.get.GetSettingsResponse;
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
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

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

    private final Client client;
    private final PluginSettings pluginSettings;
    private final Semaphore semaphore;
    private final String indexName;
    private final String mappingsPath;
    private final ObjectMapper mapper;

    /**
     * Constructor for existing indices where mapping path isn't immediately required.
     *
     * @param client The OpenSearch client.
     * @param indexName The name of the index.
     */
    public ContentIndex(Client client, String indexName) {
        this(client, indexName, null);
    }

    /**
     * Constructs a new ContentIndex manager.
     *
     * @param client The OpenSearch client used to communicate with the cluster.
     * @param indexName The name of the index to manage.
     * @param mappingsPath The classpath resource path to the JSON mapping file.
     */
    public ContentIndex(Client client, String indexName, String mappingsPath) {
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(this.pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
        this.indexName = indexName;
        this.mappingsPath = mappingsPath;
        this.mapper = new ObjectMapper();
        this.mapper.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
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
     * <p>Applies specific settings (replicas=0) and registers an alias if one is defined.
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

        Settings.Builder settingsBuilder = Settings.builder().put("index.number_of_replicas", 0);
        if (Constants.INDEX_CVES.equals(this.indexName)) {
            settingsBuilder.put("index.hidden", true);
        }
        Settings settings = settingsBuilder.build();

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
     * Indexes a new document or overwrites an existing one.
     *
     * @param id The unique identifier for the document.
     * @param payload The JSON object representing the document content.
     * @return The IndexResponse object with the result of the indexing operation.
     * @throws IOException If the indexing operation fails.
     */
    public IndexResponse create(String id, JsonNode payload) throws IOException {
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
                new IndexRequest(this.indexName)
                        .id(id)
                        .source(processedPayload.toString(), XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
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
        // 1. Fetch
        GetResponse response =
                this.client
                        .get(new GetRequest(this.indexName, id))
                        .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        if (!response.isExists()) {
            throw new IOException("Document [" + id + "] not found for update.");
        }

        // 2. Patch
        ObjectNode currentDoc = (ObjectNode) this.mapper.readTree(response.getSourceAsString());

        // Resources from the VD feed do not contain a "document" object, so we need to patch the root
        // document instead of the "document" node.
        if (this.indexName.equals(Constants.INDEX_CVES)) {
            currentDoc = (ObjectNode) currentDoc.get(Constants.KEY_DOCUMENT);
        }

        for (Operation op : operations) {
            JsonNode opJson = this.mapper.valueToTree(op);
            JsonPatch.applyOperation(currentDoc, opJson);
        }

        // 2.5. Inject offset if provided
        if (offset != null) {
            currentDoc.put(Constants.KEY_OFFSET, offset);
        }

        // 3. Process
        ObjectNode processedDoc = this.processPayload(currentDoc);

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
     * Searches for a document by a specific field name and value.
     *
     * @param queryBuilder The query to execute.
     * @return A JsonObject representing the found document, or null if not found or on
     */
    public ObjectNode searchByQuery(QueryBuilder queryBuilder) {
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
            ArrayNode hitsArray = this.mapper.createArrayNode();
            for (SearchHit hit : searchResponse.getHits().getHits()) {
                ObjectNode hitObject = (ObjectNode) this.mapper.readTree(hit.getSourceAsString());
                hitObject.put(Constants.KEY_ID, hit.getId());
                hitsArray.add(hitObject);
            }
            ObjectNode result = this.mapper.createObjectNode();
            result.set(Constants.Q_HITS, hitsArray);
            result.put("total", searchResponse.getHits().getTotalHits().value());
            return result;
        } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
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

    /**
     * Clears all documents from the index by deleting and recreating it.
     *
     * <p>No explicit mappings are applied on recreation — the setup plugin's index template is
     * automatically matched and applied by OpenSearch.
     */
    public void clear() {
        try {
            boolean exists = this.client.admin().indices().prepareExists(this.indexName).get().isExists();
            boolean isHidden = false;

            if (exists) {
                GetSettingsResponse settingsResponse =
                        this.client.admin().indices().prepareGetSettings(this.indexName).get();
                String hiddenSetting = settingsResponse.getSetting(this.indexName, "index.hidden");
                isHidden = Boolean.parseBoolean(hiddenSetting);

                this.client.admin().indices().delete(new DeleteIndexRequest(this.indexName)).actionGet();
            }

            // Recreate without explicit mappings; the setup plugin's index template is applied
            // automatically.
            CreateIndexRequest createRequest = new CreateIndexRequest(this.indexName);
            createRequest.settings(Settings.builder().put("index.hidden", isHidden));
            this.client.admin().indices().create(createRequest).actionGet();
            log.debug(
                    "[{}] wiped and recreated via template (index.hidden={})", this.indexName, isHidden);
        } catch (Exception e) {
            log.error("[{}] clear() failed: {}", this.indexName, e.getMessage());
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
            log.error("Failed to process payload via models: {}", e.getMessage(), e);
            return this.mapper.createObjectNode();
        }
    }
}
