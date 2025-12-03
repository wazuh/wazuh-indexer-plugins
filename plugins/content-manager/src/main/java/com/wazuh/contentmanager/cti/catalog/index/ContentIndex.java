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
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Manages operations for a specific Wazuh CTI Content Index.
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

    public ContentIndex(Client client, String indexName, String mappingsPath) {
        this(client, indexName, mappingsPath, null);
    }

    public ContentIndex(Client client, String indexName, String mappingsPath, String alias) {
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
        this.indexName = indexName;
        this.mappingsPath = mappingsPath;
        this.alias = alias;
        this.jsonMapper = new ObjectMapper();
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
    }

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

    public boolean exists(String id) {
        return this.client.prepareGet(this.indexName, id).setFetchSource(false).get().isExists();
    }

    public void create(String id, JsonObject payload) throws IOException {
        processPayload(payload);
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

        // 3. Process (enrich/normalize)
        processPayload(currentDoc);

        // 4. Index
        IndexRequest request = new IndexRequest(this.indexName)
            .id(id)
            .source(currentDoc.toString(), XContentType.JSON);
        this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    public void delete(String id) {
        this.client.delete(new DeleteRequest(this.indexName, id), new ActionListener<>() {
            @Override
            public void onResponse(DeleteResponse response) {
                log.debug("Deleted {} from {}", id, indexName);
            }
            @Override
            public void onFailure(Exception e) {
                log.error("Failed to delete {}: {}", id, e.getMessage());
            }
        });
    }

    public void executeBulk(BulkRequest bulkRequest) {
        try {
            this.semaphore.acquire();
            this.client.bulk(bulkRequest, new ActionListener<>() {
                @Override
                public void onResponse(BulkResponse bulkResponse) {
                    semaphore.release();
                    if (bulkResponse.hasFailures()) {
                        log.warn("Bulk indexing finished with failures: {}", bulkResponse.buildFailureMessage());
                    }
                }
                @Override
                public void onFailure(Exception e) {
                    semaphore.release();
                    log.error("Bulk indexing failed completely: {}", e.getMessage());
                }
            });
        } catch (InterruptedException e) {
            log.error("Interrupted while waiting for semaphore: {}", e.getMessage());
            Thread.currentThread().interrupt();
        }
    }

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

    private void processPayload(JsonObject payload) {
        if (payload.has("type") && "decoder".equalsIgnoreCase(payload.get("type").getAsString())) {
            enrichDecoderWithYaml(payload);
        }
        if (payload.has("document")) {
            preprocessDocument(payload.getAsJsonObject("document"));
        }
    }

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

    private void preprocessDocument(JsonObject document) {
        if (document.has("date")) {
            document.remove("date");
        }

        if (document.has("enabled")) {
            document.remove("enabled");
        }

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
                sanitizeRelatedObject(relatedElement.getAsJsonObject());
            } else if (relatedElement.isJsonArray()) {
                JsonArray relatedArray = relatedElement.getAsJsonArray();
                for (JsonElement element : relatedArray) {
                    if (element.isJsonObject()) sanitizeRelatedObject(element.getAsJsonObject());
                }
            }
        }
    }

    private void sanitizeRelatedObject(JsonObject relatedObj) {
        if (relatedObj.has("sigma_id")) {
            relatedObj.add("id", relatedObj.get("sigma_id"));
            relatedObj.remove("sigma_id");
        }
    }
}
