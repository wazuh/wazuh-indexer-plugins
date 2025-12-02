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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchTimeoutException;
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
import org.opensearch.transport.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.mapper.StrictDynamicMappingException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.model.Changes;
import com.wazuh.contentmanager.cti.catalog.model.Offset;
import com.wazuh.contentmanager.cti.catalog.model.Operation;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.cti.catalog.utils.JsonPatch;
import com.wazuh.contentmanager.utils.XContentUtils;

/**
 * Manages operations for the Wazuh CTI Content Index.
 */
public class ContentIndex {
    private static final String JSON_NAME_KEY = "name";
    private static final String JSON_OFFSET_KEY = "offset";
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    //TODO: Delete
    public static final String INDEX_NAME = "wazuh-ruleset";

    private final Client client;
    private final PluginSettings pluginSettings;
    private final Semaphore semaphore;
    private String indexName;
    private String mappingsPath;

    /**
     * Constructs a ContentIndex manager with specific settings.
     *
     * @param client       The OpenSearch client.
     * @param indexName    The name of the index to manage.
     * @param mappingsPath The classpath resource path to the index mappings file.
     */
    public ContentIndex(Client client, String indexName, String mappingsPath) {
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
        this.indexName = indexName;
        this.mappingsPath = mappingsPath;
    }

    /**
     * Creates the content index with specific settings and mappings.
     *
     * @return A {@link CreateIndexResponse} indicating success, or {@code null} if mappings could not be read.
     * @throws ExecutionException   If the creation request fails.
     * @throws InterruptedException If the thread is interrupted while waiting for the response.
     * @throws TimeoutException     If the operation exceeds the configured client timeout.
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

        return this.client
            .admin()
            .indices()
            .create(request)
            .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }


    /**
     * Executes a bulk request using the semaphore.
     *
     * @param bulkRequest The request to execute.
     */
    public void executeBulk(BulkRequest bulkRequest) {
        try {
            this.semaphore.acquire();
            this.client.bulk(bulkRequest, new ActionListener<>() {
                @Override
                public void onResponse(BulkResponse bulkResponse) {
                    semaphore.release();
                    if (bulkResponse.hasFailures()) {
                        log.warn("Bulk indexing finished with failures: {}", bulkResponse.buildFailureMessage());
                    } else {
                        log.debug("Bulk indexing successful. Indexed {} documents.", bulkResponse.getItems().length);
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

    /**
     * Constructs a ContentIndex manager using default plugin settings.
     *
     * @param client the OpenSearch Client to interact with the cluster
     */
    public ContentIndex(Client client) {
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
    }

    /**
     * Constructs a ContentIndex manager with injected settings (testing).
     *
     * @param client         Client.
     * @param pluginSettings PluginSettings.
     */
    public ContentIndex(Client client, PluginSettings pluginSettings) {
        this.pluginSettings = pluginSettings;
        this.semaphore = new Semaphore(pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
    }

    /**
     * Searches for an element in the {@link ContentIndex#INDEX_NAME} by its ID.
     *
     * @param resourceId the ID of the element to retrieve.
     * @return the element as a JsonObject instance.
     * @throws InterruptedException     if the operation is interrupted.
     * @throws ExecutionException       if an error occurs during execution.
     * @throws TimeoutException         if the operation times out.
     * @throws IllegalArgumentException if the content is not found in the index.
     */
    public JsonObject getById(String resourceId)
        throws InterruptedException, ExecutionException, TimeoutException, IllegalArgumentException {
        GetResponse response =
            this.client
                .get(new GetRequest(ContentIndex.INDEX_NAME, resourceId))
                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        if (response.isExists()) {
            return JsonParser.parseString(response.getSourceAsString()).getAsJsonObject();
        }
        throw new IllegalArgumentException(
            String.format(
                Locale.ROOT,
                "Document with ID [%s] not found in the [%s] index",
                resourceId,
                ContentIndex.INDEX_NAME));
    }

    /**
     * Indexes a single Offset document synchronously.
     *
     * @param document {@link Offset} document to index.
     * @throws StrictDynamicMappingException if the document does not match the index mappings.
     * @throws ExecutionException            if the index operation failed to execute.
     * @throws InterruptedException          if the index operation was interrupted.
     * @throws TimeoutException              if the index operation timed out.
     * @throws IOException                   if XContentBuilder creation fails.
     */
    public void index(Offset document)
        throws StrictDynamicMappingException,
        ExecutionException,
        InterruptedException,
        TimeoutException,
        IOException {
        IndexRequest indexRequest =
            new IndexRequest()
                .index(ContentIndex.INDEX_NAME)
                .source(document.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .id(document.getResource());
        this.client.index(indexRequest).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Indexes a list of JSON documents in bulk asynchronously.
     *
     * @param documents list of JSON documents to be indexed.
     */
    public void index(List<JsonObject> documents) {
        BulkRequest bulkRequest = new BulkRequest(ContentIndex.INDEX_NAME);
        for (JsonObject document : documents) {
            bulkRequest.add(
                new IndexRequest()
                    .id(document.get(ContentIndex.JSON_NAME_KEY).getAsString())
                    .source(document.toString(), XContentType.JSON));
        }

        this.client.bulk(
            bulkRequest,
            new ActionListener<>() {
                @Override
                public void onResponse(BulkResponse bulkResponse) {
                    semaphore.release();
                    if (bulkResponse.hasFailures()) {
                        log.error("Bulk index operation failed: {}", bulkResponse.buildFailureMessage());
                    } else {
                        log.debug("Bulk index operation succeeded in {} ms", bulkResponse.getTook().millis());
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    semaphore.release();
                    log.error("Bulk index operation failed: {}", e.getMessage(), e);
                }
            });
    }

    /**
     * Deletes a document from the index asynchronously.
     *
     * @param id ID of the document to delete.
     */
    public void delete(String id) {
        this.client.delete(
            new DeleteRequest(ContentIndex.INDEX_NAME, id),
            new ActionListener<>() {
                @Override
                public void onResponse(DeleteResponse response) {
                    log.info("Deleted CTI Catalog Content {} from index", id);
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to delete CTI Catalog Content {}: {}", id, e.getMessage(), e);
                }
            });
    }

    /**
     * Initializes the index from a local snapshot file.
     *
     * @param path path to the CTI snapshot JSON file to be indexed.
     * @return The offset number of the last indexed resource of the snapshot, or 0 on error/empty.
     */
    public long fromSnapshot(String path) {
        long startTime = System.currentTimeMillis();

        String line;
        JsonObject json;
        int lineCount = 0;
        ArrayList<JsonObject> items = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(path, StandardCharsets.UTF_8))) {
            while ((line = reader.readLine()) != null) {
                json = JsonParser.parseString(line).getAsJsonObject();
                items.add(json);
                lineCount++;

                // Index items (MAX_DOCUMENTS reached)
                if (lineCount == this.pluginSettings.getMaxItemsPerBulk()) {
                    this.semaphore.acquire();
                    this.index(items);
                    lineCount = 0;
                    items.clear();
                }
            }
            // Index remaining items (> MAX_DOCUMENTS)
            if (lineCount > 0) {
                this.semaphore.acquire();
                this.index(items);
            }
        } catch (InterruptedException e) {
            items.clear();
            log.error("Processing snapshot file interrupted {}", e.getMessage());
        } catch (Exception e) {
            items.clear();
            log.error("Generic exception indexing the snapshot: {}", e.getMessage());
        }
        long estimatedTime = System.currentTimeMillis() - startTime;
        log.info("Snapshot indexing finished successfully in {} ms", estimatedTime);

        return items.isEmpty()
            ? 0
            : items.get(items.size() - 1).get(ContentIndex.JSON_OFFSET_KEY).getAsLong();
    }

    /**
     * Applies a set of changes (create, update, delete) to the content index.
     *
     * @param changes content changes to apply.
     * @throws RuntimeException if the patching process is interrupted or fails.
     * @deprecated Use of this specific patch implementation may be replaced by newer synchronization methods.
     */
    public void patch(Changes changes) {
        ArrayList<Offset> offsets = changes.get();
        if (offsets.isEmpty()) {
            log.info("No changes to apply");
            return;
        }

        log.info(
            "Patching [{}] from offset [{}] to [{}]",
            ContentIndex.INDEX_NAME,
            changes.getFirst().getOffset(),
            changes.getLast().getOffset());
        for (Offset change : offsets) {
            String id = change.getResource();
            try {
                log.debug("Processing offset [{}]", change.getOffset());
                switch (change.getType()) {
                    case CREATE:
                        log.debug("Creating new resource with ID [{}]", id);
                        this.index(change);
                        break;
                    case UPDATE:
                        log.debug("Updating resource with ID [{}]", id);
                        JsonObject content = this.getById(id);
                        for (Operation op : change.getOperations()) {
                            JsonPatch.applyOperation(content, XContentUtils.xContentObjectToJson(op));
                        }
                        try (XContentParser parser = XContentUtils.createJSONParser(content)) {
                            this.index(Offset.parse(parser));
                        }
                        break;
                    case DELETE:
                        log.debug("Deleting resource with ID [{}]", id);
                        this.delete(id);
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown change type: " + change.getType());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while patching", e);
            } catch (Exception e) {
                log.error("Failed to patch [{}] due to {}", id, e.getMessage());
                throw new RuntimeException("Patch operation failed", e);
            }
        }
    }

    /**
     * Clears all documents from the {@link ContentIndex#INDEX_NAME} index using a "delete by query" operation.
     */
    public void clear() {
        try {
            DeleteByQueryRequestBuilder deleteByQuery =
                new DeleteByQueryRequestBuilder(this.client, DeleteByQueryAction.INSTANCE);
            deleteByQuery.source(this.indexName).filter(QueryBuilders.matchAllQuery());

            BulkByScrollResponse response = deleteByQuery.get();
            log.debug(
                "[{}] wiped. {} documents were removed", this.indexName, response.getDeleted());
        } catch (OpenSearchTimeoutException e) {
            log.error("[{}] delete query timed out: {}", this.indexName, e.getMessage());
        }
    }
}
