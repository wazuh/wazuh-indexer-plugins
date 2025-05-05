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
package com.wazuh.contentmanager.index;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.model.ctiapi.ContentChanges;
import com.wazuh.contentmanager.model.ctiapi.Offset;
import com.wazuh.contentmanager.model.ctiapi.PatchOperation;
import com.wazuh.contentmanager.utils.JsonPatch;
import com.wazuh.contentmanager.utils.XContentUtils;

/** Manages operations for the Wazuh CVE content index. */
public class ContentIndex {
    private static final String JSON_NAME_KEY = "name";
    private static final String JSON_OFFSET_KEY = "offset";
    private static final Logger log = LogManager.getLogger(ContentIndex.class);
    private static final int MAX_DOCUMENTS = 25;
    private static final int MAX_CONCURRENT_PETITIONS = 5;
    // The name of the index
    public static final String INDEX_NAME = "wazuh-cve";
    // The timeout for the get operation in seconds
    public static final Long TIMEOUT = 10L;

    private final Client client;
    private final Semaphore semaphore = new Semaphore(MAX_CONCURRENT_PETITIONS);

    /**
     * Constructor for the ContentIndex class.
     *
     * @param client the OpenSearch Client to interact with the cluster
     */
    public ContentIndex(Client client) {
        this.client = client;
    }

    /**
     * Indexes a single Offset document.
     *
     * @param document the Offset document to be indexed.
     */
    public void index(Offset document) {
        try {
            IndexRequest indexRequest =
                    new IndexRequest()
                            .index(INDEX_NAME)
                            .source(document.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .id(document.getResource());
            this.client.index(
                    indexRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexResponse indexResponse) {
                            log.info("Indexed CTI Catalog Content {} to index", document.getResource());
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error(
                                    "Failed to index CTI Catalog Content {}: {}",
                                    document.getResource(),
                                    e.getMessage(),
                                    e);
                        }
                    });
        } catch (IOException e) {
            log.error("Failed to create JSON content builder: {}", e.getMessage(), e);
        }
    }

    /**
     * Indexes a list of JSON documents in bulk.
     *
     * @param documents list of JSON documents to be indexed.
     */
    public void index(List<JsonObject> documents) {
        BulkRequest bulkRequest = new BulkRequest(INDEX_NAME);
        for (JsonObject document : documents) {
            bulkRequest.add(
                    new IndexRequest()
                            .id(document.get(JSON_NAME_KEY).getAsString())
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
     * Applies a set of changes (create, update, delete) to the content index.
     *
     * @param changes content changes to apply.
     */
    public void patch(ContentChanges changes) {
        if (changes.getChangesList().isEmpty()) {
            log.info("No changes to apply");
            return;
        }

        for (Offset change : changes.getChangesList()) {
            String id = change.getResource();
            try {
                log.info("Processing change: {}", change);
                switch (change.getType()) {
                    case CREATE:
                        log.debug("Creating new resource with ID [{}]", id);
                        this.index(change);
                        break;
                    case UPDATE:
                        log.debug("Updating resource with ID [{}]", id);
                        JsonObject content = this.getById(id);
                        for (PatchOperation op : change.getOperations()) {
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
                log.error("Failed to apply patch to {}: {}", id, e.getMessage(), e);
                throw new RuntimeException("Failed to apply patch operation", e);
            }
        }
    }

    /**
     * Retrieves a document from the index.
     *
     * @param id ID of the document to retrieve.
     * @return CompletableFuture containing the GetResponse.
     */
    public CompletableFuture<GetResponse> get(String id) {
        CompletableFuture<GetResponse> future = new CompletableFuture<>();
        this.client.get(
                new GetRequest(INDEX_NAME, id),
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse response) {
                        log.info("Retrieved CTI Catalog Content {} from index", id);
                        future.complete(response);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to retrieve CTI Catalog Content {}: {}", id, e.getMessage(), e);
                        future.completeExceptionally(e);
                    }
                });
        return future;
    }

    /**
     * Deletes a document from the index.
     *
     * @param id ID of the document to delete.
     */
    public void delete(String id) {
        this.client.delete(
                new DeleteRequest(INDEX_NAME, id),
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
     * Initializes the index from a local snapshot. The snapshot file (in NDJSON format) is split in
     * chunks of {@link ContentIndex#MAX_DOCUMENTS} elements. These are bulk indexed using {@link
     * ContentIndex#index(List)}.
     *
     * @param path path to the CTI snapshot JSON file to be indexed.
     * @return offset number of the last indexed resource of the snapshot. 0 on error.
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
                // Not every line in the snapshot is a CVE. We filter out the
                // content by the "name" field of the current JSON object, if
                // it starts with "CVE-". Any other case is skipped.
                String name = json.get(JSON_NAME_KEY).getAsString();
                if (name.startsWith("CVE-")) {
                    items.add(json);
                    lineCount++;
                } else {
                    log.debug("Skipping non CVE element [{}]", name);
                }

                // Index items (MAX_DOCUMENTS reached)
                if (lineCount == MAX_DOCUMENTS) {
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

        return items.isEmpty() ? 0 : items.get(items.size() - 1).get(JSON_OFFSET_KEY).getAsLong();
    }

    /**
     * Searches for an element in the {@link ContentIndex#INDEX_NAME} by its ID.
     *
     * @param resourceId the ID of the element to retrieve.
     * @return the element as a JsonObject instance.
     * @throws InterruptedException if the operation is interrupted.
     * @throws ExecutionException if an error occurs during execution.
     * @throws TimeoutException if the operation times out.
     * @throws IllegalArgumentException if the content is not found.
     */
    public JsonObject getById(String resourceId)
            throws InterruptedException, ExecutionException, TimeoutException, IllegalArgumentException {
        GetResponse response = this.get(resourceId).get(TIMEOUT, TimeUnit.SECONDS);
        if (response.isExists()) {
            return JsonParser.parseString(response.getSourceAsString()).getAsJsonObject();
        }
        // else
        throw new IllegalArgumentException(
                String.format(
                        Locale.ROOT,
                        "Document with ID [%s] not found in the [%s] index",
                        resourceId,
                        INDEX_NAME));
    }

    /**
     * Checks if the index exists.
     *
     * @return true if the index exists, false otherwise.
     */
    public boolean exists() {
        IndicesExistsRequest request = new IndicesExistsRequest(INDEX_NAME);
        IndicesExistsResponse response = this.client.admin().indices().exists(request).actionGet();
        return response.isExists();
    }

    //    /**
    //     * Retrieves the last indexed offset to the {@link ContentIndex#INDEX_NAME} index.
    //     *
    //     * @return Long value with the last indexed offset.
    //     */
    //    public Long getOffset() {
    //        return this.offset;
    //    }
}
