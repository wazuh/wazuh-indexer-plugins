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
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import com.wazuh.contentmanager.model.ctiapi.ContextChanges;
import com.wazuh.contentmanager.model.ctiapi.PatchChange;
import com.wazuh.contentmanager.model.ctiapi.PatchOperation;
import com.wazuh.contentmanager.util.JsonPatch;

/** Class to manage the Content Manager index. */
public class ContentIndex {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    private static final String INDEX_NAME = "wazuh-cve";
    private final int MAX_DOCUMENTS = 25;
    private static final int MAX_CONCURRENT_PETITIONS = 5;
    public static final Long TIMEOUT = 10L;

    private final Client client;
    private final Semaphore semaphore = new Semaphore(MAX_CONCURRENT_PETITIONS);

    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     */
    public ContentIndex(Client client) {
        this.client = client;
    }

    public void index(PatchChange document) {
        IndexRequest indexRequest = null;
        try {
            indexRequest =
                    new IndexRequest()
                            .index(INDEX_NAME)
                            .source(document.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .id(document.getResource())
                            .create(true);
        } catch (IOException e) {
            log.error("Failed to create JSON content builder: {}", e.getMessage());
        }
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
                                "Failed to index CTI Catalog Content {}, Exception: {}",
                                document.getResource(),
                                e.getStackTrace());
                    }
                });
    }

    /**
     * Index an array of JSON objects using a BulkRequest
     *
     * @param documents the array of objects
     */
    private void indexBulk(List<JsonObject> documents) {
        BulkRequest bulkRequest = new BulkRequest(INDEX_NAME);
        log.info("Indexing {} documents", documents.size());
        for (JsonObject document : documents) {
            bulkRequest.add(
                    new IndexRequest()
                            .id(document.get("name").getAsString())
                            .source(document.toString(), XContentType.JSON));
        }

        client.bulk(
                bulkRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(BulkResponse bulkResponse) {
                        semaphore.release();
                        if (bulkResponse.hasFailures()) {
                            log.error(
                                    "Snapshot indexing bulk request failed: {}", bulkResponse.buildFailureMessage());
                        } else {
                            log.debug(
                                    "Snapshot indexing bulk request was successful: took [{}]ms",
                                    bulkResponse.getTook().millis());
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        semaphore.release();
                        log.error("Snapshot indexing bulk request has failed: {}", e.getMessage());
                    }
                });
    }

    /**
     * Patch the content of the current snapshot with the changes provided in JSON Patch format.
     *
     * @param changes the ContextChanges to patch the existing document.
     */
    public void patch(ContextChanges changes)
            throws RuntimeException,
                    ExecutionException,
                    InterruptedException,
                    TimeoutException,
                    IOException {
        if (changes.getChangesList().isEmpty()) {
            log.info("No changes to apply");
            return;
        }
        // Iterate over the changes and apply them
        for (PatchChange change : changes.getChangesList()) {
            log.info("Processing change: {}", change);
            switch (change.getType()) {
                case CREATE:
                    log.info("Creating new resource: {}", change.getResource());
                    this.index(change);
                    break;

                case UPDATE:
                    XContent xContent = XContentType.JSON.xContent();
                    GetResponse getResponseUpdate =
                            this.get(change.getResource()).get(TIMEOUT, TimeUnit.SECONDS);
                    if (!getResponseUpdate.isExists()) {
                        throw new IllegalArgumentException("Document not found");
                    }
                    JsonObject existingDoc =
                            JsonParser.parseString(getResponseUpdate.getSourceAsString()).getAsJsonObject();
                    JsonPatch jsonPatch = new JsonPatch();
                    for (PatchOperation operation : change.getOperations()) {
                        jsonPatch.applyOperation(existingDoc, operation.getValueAsJson());
                    }

                    this.index(
                            PatchChange.parse(
                                    xContent.createParser(
                                            NamedXContentRegistry.EMPTY,
                                            DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                            change.toString())));
                    break;
                case DELETE:
                    GetResponse getResponseDelete =
                            this.get(change.getResource()).get(TIMEOUT, TimeUnit.SECONDS);
                    if (!getResponseDelete.isExists()) {
                        throw new IllegalArgumentException("Document not found");
                    }
                    DeleteRequest deleteRequest = new DeleteRequest(INDEX_NAME, change.getResource());
                    client.delete(deleteRequest);
                    break;
                default:
                    log.error("Unknown change type: {}", change.getType());
                    throw new IllegalArgumentException("Unknown change type: " + change.getType());
            }
        }
    }

    public CompletableFuture<GetResponse> get(String id) {
        CompletableFuture<GetResponse> future = new CompletableFuture<>();
        GetRequest getRequest = new GetRequest(INDEX_NAME, id);
        client.get(
                getRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse getResponse) {
                        log.info("Retrieved CTI Catalog Content {} from index", id);
                        future.complete(getResponse);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to retrieve CTI Catalog Content {}, Exception: {}", id, e);
                        future.completeExceptionally(e);
                    }
                });
        return future;
    }

    /**
     * Initializes the index from a local snapshot. The snapshot file (in NDJSON format) is split in
     * chunks of {@link ContentIndex#MAX_DOCUMENTS} elements. These are bulk indexed using {@link
     * ContentIndex#indexBulk(List)}.
     *
     * @param path path to the CTI snapshot JSON file to be indexed.
     */
    public void fromSnapshot(String path) {
        long startTime = System.currentTimeMillis();

        String line;
        JsonObject json;
        int lineCount = 0;
        ArrayList<JsonObject> items = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(path, StandardCharsets.UTF_8))) {
            while ((line = reader.readLine()) != null) {
                json = JsonParser.parseString(line).getAsJsonObject();
                // Not every line in the snapshot is a CVE. We filter out the content by the "name" field of
                // the
                // current JSON object, if it starts with "CVE-". Any other case is skipped.
                String name = json.get("name").getAsString();
                if (name.startsWith("CVE-")) {
                    items.add(json);
                    lineCount++;
                } else {
                    log.debug("Skipping non CVE element [{}]", name);
                }

                // Index items (MAX_DOCUMENTS reached)
                if (lineCount == MAX_DOCUMENTS) {
                    semaphore.acquire();
                    this.indexBulk(items);
                    lineCount = 0;
                    items.clear();
                }
            }
            // Index remaining items (> MAX_DOCUMENTS)
            if (lineCount > 0) {
                semaphore.acquire();
                this.indexBulk(items);
            }
        } catch (Exception e) {
            log.error("Error processing snapshot file {}", e.getMessage());
        }
        long estimatedTime = System.currentTimeMillis() - startTime;
        log.info("Snapshot indexing finished successfully in {} ms", estimatedTime);
    }
}
