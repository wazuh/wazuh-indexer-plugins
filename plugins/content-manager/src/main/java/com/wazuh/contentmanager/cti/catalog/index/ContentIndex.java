/*
 * Copyright (C) 2024, Wazuh Inc.
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
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.wazuh.contentmanager.cti.catalog.model.Operation;
import com.wazuh.contentmanager.cti.catalog.utils.JsonPatch;
import com.wazuh.contentmanager.settings.PluginSettings;
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
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Manages operations for a specific Wazuh CTI Content Index.
 * <p>
 * This class handles the lifecycle of the index (creation, deletion) as well as
 * CRUD operations for documents, including specialized logic for parsing
 * and sanitizing CTI content payloads.
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
    private final ObjectMapper yamlMapper;
    private static final List<String> DECODER_ORDER_KEYS = Arrays.asList(
        "name", "metadata", "parents", "definitions", "check",
        "parse|event.original", "parse|message", "normalize"
    );

    private enum spaceName { free, paid, custom }

    /**
     * Constructs a new ContentIndex manager.
     *
     * @param client       The OpenSearch client used to communicate with the cluster.
     * @param indexName    The name of the index to manage.
     * @param mappingsPath The classpath resource path to the JSON mapping file.
     */
    public ContentIndex(Client client, String indexName, String mappingsPath) {
        this(client, indexName, mappingsPath, null);
    }

    /**
     * Constructs a new ContentIndex manager with an alias.
     *
     * @param client       The OpenSearch client used to communicate with the cluster.
     * @param indexName    The name of the index to manage.
     * @param mappingsPath The classpath resource path to the JSON mapping file.
     * @param alias        The alias to associate with the index (can be null).
     */
    public ContentIndex(Client client, String indexName, String mappingsPath, String alias) {
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(this.pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
        this.indexName = indexName;
        this.mappingsPath = mappingsPath;
        this.alias = alias;
        this.jsonMapper = new ObjectMapper();
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
    }

    /**
     * Creates the index in OpenSearch using the configured mappings and settings.
     * <p>
     * Applies specific settings (hidden=true, replicas=0) and registers an alias if one is defined.
     *
     * @return The response from the create index operation, or null if mappings could not be read.
     * @throws ExecutionException   If the client execution fails.
     * @throws InterruptedException If the thread is interrupted while waiting.
     * @throws TimeoutException     If the operation exceeds the client timeout setting.
     */
    public CreateIndexResponse createIndex() throws ExecutionException, InterruptedException, TimeoutException {
        Settings settings = Settings.builder()
            .put("index.number_of_replicas", 0)
            .put("hidden", true)
            .build();

        String mappings;
        try (InputStream is = this.getClass().getResourceAsStream(this.mappingsPath)) {
            mappings = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("Could not read mappings for index [{}]", this.indexName);
            return null;
        }

        CreateIndexRequest request = new CreateIndexRequest()
            .index(this.indexName)
            .mapping(mappings)
            .settings(settings);

        if (this.alias != null && !this.alias.isEmpty()) {
            request.alias(new Alias(this.alias));
        }

        return this.client.admin().indices().create(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
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
     * <p>
     * The payload is pre-processed (sanitized and enriched) before being indexed.
     *
     * @param id      The unique identifier for the document.
     * @param payload The JSON object representing the document content.
     * @throws IOException If the indexing operation fails.
     */
    public void create(String id, JsonObject payload) throws IOException {
        this.processPayload(payload);
        IndexRequest request = new IndexRequest(this.indexName)
            .id(id)
            .source(payload.toString(), XContentType.JSON);

        try {
            this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        } catch (Exception e) {
            log.error("Failed to index document [{}]: {}", id, e.getMessage());
            throw new IOException(e);
        }
    }

    /**
     * Updates an existing document by applying a list of patch operations.
     *
     * @param id         The ID of the document to update.
     * @param operations The list of operations to apply to the document.
     * @throws Exception If the document does not exist, or if patching/indexing fails.
     */
    public void update(String id, List<Operation> operations) throws Exception {
        // 1. Fetch
        GetResponse response = this.client.get(new GetRequest(this.indexName, id)).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
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
        this.processPayload(currentDoc);

        // 4. Index
        IndexRequest request = new IndexRequest(this.indexName)
            .id(id)
            .source(currentDoc.toString(), XContentType.JSON);
        this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Asynchronously deletes a document from the index.
     *
     * @param id The ID of the document to delete.
     */
    public void delete(String id) {
        this.client.delete(new DeleteRequest(this.indexName, id), new ActionListener<>() {
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
     * Executes a bulk request asynchronously.
     *
     * @param bulkRequest The BulkRequest containing multiple index/delete operations.
     */
    public void executeBulk(BulkRequest bulkRequest) {
        try {
            this.semaphore.acquire();
            this.client.bulk(bulkRequest, new ActionListener<>() {
                @Override
                public void onResponse(BulkResponse bulkResponse) {
                    ContentIndex.this.semaphore.release();
                    if (bulkResponse.hasFailures()) {
                        log.warn("Bulk indexing finished with failures: {}", bulkResponse.buildFailureMessage());
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
     * Deletes all documents in the index using a "match_all" query.
     */
    public void clear() {
        try {
            DeleteByQueryRequestBuilder deleteByQuery = new DeleteByQueryRequestBuilder(this.client, DeleteByQueryAction.INSTANCE);
            deleteByQuery.source(this.indexName).filter(QueryBuilders.matchAllQuery());
            BulkByScrollResponse response = deleteByQuery.get();
            log.debug("[{}] wiped. {} documents removed", this.indexName, response.getDeleted());
        } catch (OpenSearchTimeoutException e) {
            log.error("[{}] delete query timed out: {}", this.indexName, e.getMessage());
        }
    }

    /**
     * Orchestrates the enrichment and sanitization of a payload.
     *
     * @param payload The JSON payload to process.
     */
    public void processPayload(JsonObject payload) {
        // 1. Enrich decoder if type is 'decoder'
        if (payload.has("type") && "decoder".equalsIgnoreCase(payload.get("type").getAsString())) {
            this.enrichDecoderWithYaml(payload);
        }

        JsonObject document = null;
        String decoder = null;

        // 2. Extract and sanitize the document
        if (payload.has("document") && payload.get("document").isJsonObject()) {
            document = payload.getAsJsonObject("document");
            preprocessDocument(document);
        }

        // 3. Extract decoder YAML if present
        if (payload.has("decoder") && !payload.get("decoder").isJsonNull()) {
            decoder = payload.get("decoder").getAsString();
        }

        // 4. Calculate checksum based on the sanitized document content
        String hash = (document != null) ? this.calculateSha256(document) : null;

        // 5. Clear existing fields to remove unwanted metadata
        List<String> keysToRemove = new ArrayList<>(payload.keySet());
        for (String key : keysToRemove) {
            payload.remove(key);
        }

        // 6. Rebuild the payload with only 'document', 'hash.sha256', and 'decoder'
        if (document != null) {
            payload.add("document", document);
        }
        if (hash != null) {
            payload.addProperty("hash.sha256", hash);
        }
        if (decoder != null) {
            payload.addProperty("decoder", decoder);
        }
        // TODO: Once CTI is ready change to actual real logic
        payload.addProperty("space.name", spaceName.free.toString());
    }

    /**
     * Generates a YAML representation for decoder documents.
     *
     * @param payload The payload containing the decoder definition.
     */
    private void enrichDecoderWithYaml(JsonObject payload) {
        try {
            if (!payload.has("document")) return;
            JsonNode docNode = this.jsonMapper.readTree(payload.get("document").toString());

            if (docNode != null && docNode.isObject()) {
                Map<String, Object> orderedDecoderMap = new LinkedHashMap<>();
                for (String key : DECODER_ORDER_KEYS) {
                    if (docNode.has(key)) orderedDecoderMap.put(key, docNode.get(key));
                }
                Iterator<Map.Entry<String, JsonNode>> fields = docNode.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> field = fields.next();
                    if (!DECODER_ORDER_KEYS.contains(field.getKey())) {
                        orderedDecoderMap.put(field.getKey(), field.getValue());
                    }
                }
                payload.addProperty("decoder", this.yamlMapper.writeValueAsString(orderedDecoderMap));
            }
        } catch (IOException e) {
            log.error("Failed to convert decoder payload to YAML: {}", e.getMessage(), e);
        }
    }

    /**
     * Sanitizes the document by removing internal or unnecessary fields.
     * <p>
     * This removes fields like 'date', 'enabled', and internal metadata, and
     * normalizes 'related' objects.
     *
     * @param document The document object to preprocess.
     */
    private void preprocessDocument(JsonObject document) {
        if (document.has("metadata") && document.get("metadata").isJsonObject()) {
            JsonObject metadata = document.getAsJsonObject("metadata");
            if (metadata.has("custom_fields")) {
                metadata.remove("custom_fields");
            }
            if (metadata.has("dataset")) {
                metadata.remove("dataset");
            }
        }

        if (document.has("related")) {
            JsonElement relatedElement = document.get("related");
            if (relatedElement.isJsonObject()) {
                this.sanitizeRelatedObject(relatedElement.getAsJsonObject());
            } else if (relatedElement.isJsonArray()) {
                JsonArray relatedArray = relatedElement.getAsJsonArray();
                for (JsonElement element : relatedArray) {
                    if (element.isJsonObject()) this.sanitizeRelatedObject(element.getAsJsonObject());
                }
            }
        }
    }

    /**
     * Normalizes a "related" object.
     *
     * @param relatedObj The related object to sanitize.
     */
    private void sanitizeRelatedObject(JsonObject relatedObj) {
        if (relatedObj.has("sigma_id")) {
            relatedObj.add("id", relatedObj.get("sigma_id"));
            relatedObj.remove("sigma_id");
        }
    }

    /**
     * Calculates the SHA-256 checksum of a JSON Object.
     *
     * @param json The JSON object to hash.
     * @return The hex string representation of the hash.
     */
    private String calculateSha256(JsonObject json) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(json.toString().getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
            for (byte b : encodedhash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            log.error("Failed to calculate SHA-256 hash", e);
            return null;
        }
    }
}
