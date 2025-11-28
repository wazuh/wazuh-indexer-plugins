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
package com.wazuh.contentmanager.cti.catalog.service;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.cti.catalog.index.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.utils.Unzip;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.env.Environment;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Locale;
import java.util.concurrent.Semaphore;

/**
 * Service responsible for handling the download, extraction, and indexing of CTI snapshots.
 * It extracts the inner 'document' from the snapshot payload and indexes it into
 * dynamically named indices based on the payload type.
 */
public class SnapshotService {
    private static final Logger log = LogManager.getLogger(SnapshotService.class);

    // Keys to navigate the JSON structure
    private static final String JSON_PAYLOAD_KEY = "payload";
    private static final String JSON_TYPE_KEY = "type";
    private static final String JSON_DOCUMENT_KEY = "document";
    private static final String JSON_ID_KEY = "id";

    private final String context;
    private final String consumer;
    private final CTIClient ctiClient;
    private final Client openSearchClient;
    private final Environment environment;
    private final PluginSettings pluginSettings;

    private final Semaphore semaphore;

    /**
     * Constructor.
     *
     * @param context          The context identifier (e.g., rules_development_0.0.1).
     * @param consumer         The consumer identifier (e.g., rules_consumer).
     * @param ctiClient        Client to download the snapshot.
     * @param openSearchClient OpenSearch client for indexing.
     * @param environment      Environment to handle temporary paths.
     */
    public SnapshotService(String context,
                           String consumer,
                           CTIClient ctiClient,
                           Client openSearchClient,
                           Environment environment) {
        this.context = context;
        this.consumer = consumer;
        this.ctiClient = ctiClient;
        this.openSearchClient = openSearchClient;
        this.environment = environment;
        this.pluginSettings = PluginSettings.getInstance();
        this.semaphore = new Semaphore(this.pluginSettings.getMaximumConcurrentBulks());
    }

    /**
     * Initializes the content by downloading the snapshot from the given link,
     * unzipping it, and indexing the content into specific indices.
     *
     * @param snapshotUrl  The URL to download the snapshot from.
     * @param remoteOffset The remote offset that was processed (to update consumer state).
     */
    public void initialize(String snapshotUrl, long remoteOffset) {
        if (snapshotUrl == null || snapshotUrl.isEmpty()) {
            log.warn("Snapshot URL is empty. Skipping initialization.");
            return;
        }

        log.info("Starting snapshot initialization for context [{}] consumer [{}]", this.context, this.consumer);
        Path snapshotZip = null;
        Path outputDir = null;

        try {
            // 1. Download Snapshot
            snapshotZip = this.ctiClient.download(snapshotUrl, this.environment);
            if (snapshotZip == null) {
                log.error("Failed to download snapshot from {}", snapshotUrl);
                return;
            }

            // 2. Prepare output directory
            outputDir = this.environment.tmpDir().resolve("snapshot_" + System.currentTimeMillis());
            Files.createDirectories(outputDir);

            // 3. Unzip
            Unzip.unzip(snapshotZip, outputDir);

            // 4. Process and Index Files
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(outputDir, "*.json")) {
                for (Path entry : stream) {
                    processSnapshotFile(entry);
                }
            }

            // 5. Update Consumer State in .cti-consumers
            try {
                String id = String.format(Locale.ROOT, "%s_%s", this.context, this.consumer);
                JsonObject consumerState = new JsonObject();
                consumerState.addProperty("context", this.context);
                consumerState.addProperty("name", this.consumer);
                consumerState.addProperty("local_offset", remoteOffset);
                consumerState.addProperty("remote_offset", remoteOffset);
                consumerState.addProperty("snapshot_link", snapshotUrl);

                IndexRequest indexRequest = new IndexRequest(ConsumersIndex.INDEX_NAME)
                    .id(id)
                    .source(consumerState.toString(), XContentType.JSON);

                this.openSearchClient.index(indexRequest).actionGet();
                log.info("Consumer state updated successfully in {} for [{}]", ConsumersIndex.INDEX_NAME, id);
            } catch (Exception e) {
                log.error("Failed to update consumer state in {}: {}", ConsumersIndex.INDEX_NAME, e.getMessage());
            }

        } catch (IOException e) {
            log.error("Error processing snapshot: {}", e.getMessage(), e);
        } finally {
            // Cleanup temporary files
            cleanup(snapshotZip, outputDir);
        }
    }

    /**
     * Reads a JSON snapshot file line by line, extracts the payload document,
     * and indexes it into the corresponding type index.
     *
     * @param filePath Path to the JSON file.
     */
    private void processSnapshotFile(Path filePath) {
        String line;
        int docCount = 0;
        BulkRequest bulkRequest = new BulkRequest();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toFile(), StandardCharsets.UTF_8))) {
            while ((line = reader.readLine()) != null) {
                try {
                    // Parse root object
                    JsonObject rootJson = JsonParser.parseString(line).getAsJsonObject();

                    // 1. Validate and Extract Payload
                    if (!rootJson.has(JSON_PAYLOAD_KEY)) {
                        log.warn("Snapshot entry missing '{}'. Skipping.", JSON_PAYLOAD_KEY);
                        continue;
                    }
                    JsonObject payload = rootJson.getAsJsonObject(JSON_PAYLOAD_KEY);

                    // 2. Determine Index from 'type' inside payload
                    if (!payload.has(JSON_TYPE_KEY)) {
                        log.warn("Payload missing '{}'. Skipping.", JSON_TYPE_KEY);
                        continue;
                    }
                    String type = payload.get(JSON_TYPE_KEY).getAsString();

                    // Skip policy type documents
                    if ("policy".equalsIgnoreCase(type)) {
                        log.debug("Skipping document with type {}.", type);
                        continue;
                    }

                    String indexName = String.format(Locale.ROOT, ".%s-%s-%ss", this.context, this.consumer, type);

                    // 3. Extract the 'document' object to index
                    if (!payload.has(JSON_DOCUMENT_KEY)) {
                        log.warn("Payload missing '{}'. Skipping.", JSON_DOCUMENT_KEY);
                        continue;
                    }
                    JsonObject documentToIndex = payload.getAsJsonObject(JSON_DOCUMENT_KEY);

                    // Preprocess documents that don't follow the schema
                    preprocessDocument(documentToIndex);

                    // 4. Create Index Request
                    IndexRequest indexRequest = new IndexRequest(indexName)
                        .source(documentToIndex.toString(), XContentType.JSON);

                    // Use the inner document ID if available (e.g., "id": "c86e6f81...")
                    if (documentToIndex.has(JSON_ID_KEY)) {
                        indexRequest.id(documentToIndex.get(JSON_ID_KEY).getAsString());
                    }

                    bulkRequest.add(indexRequest);
                    docCount++;

                    // Execute Bulk if limit reached
                    if (docCount >= this.pluginSettings.getMaxItemsPerBulk()) {
                        executeBulk(bulkRequest);
                        bulkRequest = new BulkRequest();
                        docCount = 0;
                    }

                } catch (Exception e) {
                    log.error("Error parsing/indexing JSON line: {}", e.getMessage());
                }
            }

            // Index remaining documents
            if (bulkRequest.numberOfActions() > 0) {
                executeBulk(bulkRequest);
            }

        } catch (IOException e) {
            log.error("Error reading snapshot file [{}]: {}", filePath, e.getMessage());
        }
    }

    /**
     * Preprocesses the document to handle field transformations.
     * Specifically, renames 'related.sigma_id' to 'related.id' to avoid StrictDynamicMappingException.
     *
     * @param document The JSON document object to process.
     */
    private void preprocessDocument(JsonObject document) {
        if (!document.has("related")) {
            return;
        }

        JsonElement relatedElement = document.get("related");

        if (relatedElement.isJsonObject()) {
            sanitizeRelatedObject(relatedElement.getAsJsonObject());
        } else if (relatedElement.isJsonArray()) {
            JsonArray relatedArray = relatedElement.getAsJsonArray();
            for (JsonElement element : relatedArray) {
                if (element.isJsonObject()) {
                    sanitizeRelatedObject(element.getAsJsonObject());
                }
            }
        }
    }

    /**
     * Helper method to perform the actual rename/delete logic on a specific related object.
     *
     * @param relatedObj The specific related object (either standalone or from an array).
     */
    private void sanitizeRelatedObject(JsonObject relatedObj) {
        if (relatedObj.has("sigma_id")) {
            JsonElement sigmaIdValue = relatedObj.get("sigma_id");
            // Move value to 'id'
            relatedObj.add("id", sigmaIdValue);
            // Remove the original 'sigma_id' field
            relatedObj.remove("sigma_id");
        }
    }

    /**
     * Executes a bulk request using the OpenSearch client with semaphore control.
     *
     * @param bulkRequest The request to execute.
     */
    private void executeBulk(BulkRequest bulkRequest) {
        try {
            this.semaphore.acquire();
            this.openSearchClient.bulk(bulkRequest, new ActionListener<BulkResponse>() {
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
     * Deletes temporary files and directories used during the process.
     */
    private void cleanup(Path zipFile, Path directory) {
        try {
            if (zipFile != null) Files.deleteIfExists(zipFile);
            if (directory != null) {
                Files.walk(directory)
                    .sorted((a, b) -> b.compareTo(a))
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            log.warn("Failed to delete temp file {}", path);
                        }
                    });
            }
        } catch (IOException e) {
            log.warn("Error during cleanup: {}", e.getMessage());
        }
    }
}
