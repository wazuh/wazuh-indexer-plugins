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
import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.model.cti.Changes;
import com.wazuh.contentmanager.model.cti.Offset;
import com.wazuh.contentmanager.model.cti.Operation;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.JsonPatch;
import com.wazuh.contentmanager.utils.XContentUtils;

/** Manages operations for a content index. */
public class ContentIndex {
    private static final String JSON_NAME_KEY = "name";
    private static final String JSON_OFFSET_KEY = "offset";
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    /** Content index name. */
    public static final String INDEX_NAME = "wazuh-cve";

    private final Client client;
    private final PluginSettings pluginSettings;
    private final Semaphore semaphore;

    /**
     * Constructor for the ContentIndex class.
     *
     * @param client the OpenSearch Client to interact with the cluster
     */
    public ContentIndex(Client client) {
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(pluginSettings.getMaximumConcurrentBulks());
        this.client = client;
    }

    /**
     * This constructor is only used on tests.
     *
     * @param client @Client (mocked).
     * @param pluginSettings @PluginSettings (mocked).
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
     * @return the element as a JsonObject instance, or null.
     * @throws InterruptedException if the operation is interrupted.
     * @throws ExecutionException if an error occurs during execution.
     * @throws TimeoutException if the operation times out.
     * @throws IllegalArgumentException if the content is not found.
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
     * Indexes a single Offset document.
     *
     * @param document {@link Offset} document to index.
     * @throws StrictDynamicMappingException index operation failed because the document does not
     *     match the index mappings.
     * @throws ExecutionException index operation failed to execute.
     * @throws InterruptedException index operation was interrupted.
     * @throws TimeoutException index operation timed out.
     * @throws IOException operation failed caused by the creation of the JSON builder by the
     *     XContentFactory.
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
     * Indexes a list of JSON documents in bulk.
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
     * Deletes a document from the index.
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
     * Initializes the index from a local snapshot. The snapshot file (in NDJSON format) is split in
     * chunks of {@link PluginSettings#MAX_ITEMS_PER_BULK} elements. These are bulk indexed using
     * {@link ContentIndex#index(List)}.
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
                String name = json.get(ContentIndex.JSON_NAME_KEY).getAsString();
                if (name.startsWith("CVE-")) {
                    items.add(json);
                    lineCount++;
                } else {
                    log.debug("Skipping non CVE element [{}]", name);
                }

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

    /** Clears all documents from the {@link ContentIndex#INDEX_NAME} index. */
    public void clear() {
        try {
            DeleteByQueryRequestBuilder deleteByQuery =
                    new DeleteByQueryRequestBuilder(this.client, DeleteByQueryAction.INSTANCE);
            deleteByQuery.source(ContentIndex.INDEX_NAME).filter(QueryBuilders.matchAllQuery());

            BulkByScrollResponse response = deleteByQuery.get();
            log.debug(
                    "[{}] wiped. {} documents were removed", ContentIndex.INDEX_NAME, response.getDeleted());
        } catch (OpenSearchTimeoutException e) {
            log.error("[{}] delete query timed out: {}", ContentIndex.INDEX_NAME, e.getMessage());
        }
    }
}
