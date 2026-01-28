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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.Environment;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.client.SnapshotClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.utils.Unzip;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Service responsible for handling the download, extraction, and indexing of CTI snapshots. It
 * extracts the contents of the payload and indexes them at the root.
 */
public class SnapshotServiceImpl implements SnapshotService {
    private static final Logger log = LogManager.getLogger(SnapshotServiceImpl.class);

    // Keys to navigate the JSON structure
    private static final String JSON_PAYLOAD_KEY = "payload";
    private static final String JSON_TYPE_KEY = "type";
    private static final String JSON_DOCUMENT_KEY = "document";
    private static final String JSON_ID_KEY = "id";

    private final String context;
    private final String consumer;
    private final Map<String, ContentIndex> indicesMap;
    private final ConsumersIndex consumersIndex;
    private SnapshotClient snapshotClient;
    private final Environment environment;
    private final PluginSettings pluginSettings;

    /**
     * Constructs a new SnapshotServiceImpl.
     *
     * @param context The context of the snapshot.
     * @param consumer The consumer identifier.
     * @param indicesMap A map of content types to their corresponding ContentIndex.
     * @param consumersIndex The consumers index to update consumer state.
     * @param environment The OpenSearch environment.
     */
    public SnapshotServiceImpl(
            String context,
            String consumer,
            Map<String, ContentIndex> indicesMap,
            ConsumersIndex consumersIndex,
            Environment environment) {
        this.context = context;
        this.consumer = consumer;
        this.indicesMap = indicesMap;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
        this.pluginSettings = PluginSettings.getInstance();

        this.snapshotClient = new SnapshotClient(this.environment);
    }

    /**
     * Used for testing. Inject mocks.
     *
     * @param client The SnapshotClient to use.
     */
    public void setSnapshotClient(SnapshotClient client) {
        this.snapshotClient = client;
    }

    /**
     * Initializes the content by downloading the snapshot from the given link, unzipping it, and
     * indexing the content into specific indices.
     *
     * @param consumer information from the remote consumer. Contains the snapshot link from which the
     *     initialization takes place.
     */
    @Override
    public void initialize(RemoteConsumer consumer) {
        String snapshotUrl = consumer.getSnapshotLink();

        if (snapshotUrl == null || snapshotUrl.isEmpty()) {
            log.warn("Snapshot URL is empty. Skipping initialization.");
            return;
        }

        log.info(
                "Starting snapshot initialization for context [{}] consumer [{}]",
                this.context,
                this.consumer);
        Path snapshotZip = null;
        Path outputDir = null;

        try {
            // 1. Download Snapshot
            snapshotZip = this.snapshotClient.downloadFile(snapshotUrl);
            if (snapshotZip == null) {
                log.error("Failed to download snapshot from {}", snapshotUrl);
                return;
            }

            // 2. Prepare output directory
            outputDir = this.environment.tmpDir().resolve("snapshot_" + System.currentTimeMillis());
            Files.createDirectories(outputDir);

            // 3. Unzip
            Unzip.unzip(snapshotZip, outputDir);

            // 4. Clear indices
            this.indicesMap.values().forEach(ContentIndex::clear);

            // 5. Process and Index Files
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(outputDir, "*.json")) {
                for (Path entry : stream) {
                    this.processSnapshotFile(entry);
                }
            }

            // Ensure all bulk requests are finished
            if (!this.indicesMap.isEmpty()) {
                log.info("Waiting for pending bulk updates to finish...");
                this.indicesMap.values().iterator().next().waitForPendingUpdates();
            }

        } catch (Exception e) {
            log.error("Error processing snapshot: {}", e.getMessage());
        } finally {
            // Cleanup temporary files
            this.cleanup(snapshotZip, outputDir);
        }

        // 6. Update Consumer State in .cti-consumers
        try {
            LocalConsumer updatedConsumer =
                    new LocalConsumer(
                            this.context,
                            this.consumer,
                            consumer.getSnapshotOffset(),
                            consumer.getOffset(),
                            snapshotUrl);
            this.consumersIndex.setConsumer(updatedConsumer);
        } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Failed to update consumer state in {}: {}", ConsumersIndex.INDEX_NAME, e.getMessage());
        }
    }

    /**
     * Reads a JSON snapshot file line by line, extracts the contents of the payload object, and
     * indexes them directly at the root.
     *
     * @param filePath Path to the JSON file.
     */
    private void processSnapshotFile(Path filePath) {
        String line;
        int docCount = 0;
        BulkRequest bulkRequest = new BulkRequest();

        // Use any available index to execute the bulk request
        ContentIndex executorIndex = this.indicesMap.isEmpty() ? null : this.indicesMap.values().iterator().next();
        if (executorIndex == null) {
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(filePath, StandardCharsets.UTF_8)) {
            while ((line = reader.readLine()) != null) {
                try {
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

                    // 3. Select correct index based on type
                    ContentIndex indexHandler = this.indicesMap.get(type);
                    if (indexHandler == null) {
                        log.warn("No ContentIndex found for type [{}]. Skipping.", type);
                        continue;
                    }

                    JsonObject processedPayload = indexHandler.processPayload(payload);
                    String indexName = indexHandler.getIndexName();

                    // 4. Create Index Request
                    IndexRequest indexRequest =
                            new IndexRequest(indexName).source(processedPayload.toString(), XContentType.JSON);

                    // Determine ID
                    if (processedPayload.has(JSON_DOCUMENT_KEY)) {
                        JsonObject innerDocument = processedPayload.getAsJsonObject(JSON_DOCUMENT_KEY);
                        if (innerDocument.has(JSON_ID_KEY)) {
                            indexRequest.id(innerDocument.get(JSON_ID_KEY).getAsString());
                        }
                    }

                    bulkRequest.add(indexRequest);
                    docCount++;

                    // Execute Bulk if limit reached
                    if (docCount >= this.pluginSettings.getMaxItemsPerBulk()) {
                        executorIndex.executeBulk(bulkRequest);
                        bulkRequest = new BulkRequest();
                        docCount = 0;
                    }

                } catch (JsonSyntaxException e) {
                    log.error("Error parsing/indexing JSON line: {}", e.getMessage());
                }
            }

            // Index remaining documents
            if (bulkRequest.numberOfActions() > 0) {
                executorIndex.executeBulk(bulkRequest);
            }

        } catch (IOException e) {
            log.error("Error reading snapshot file [{}]: {}", filePath, e.getMessage());
        }
    }

    /** Deletes temporary files and directories used during the process. */
    private void cleanup(Path zipFile, Path directory) {
        try {
            if (zipFile != null) {
                Files.deleteIfExists(zipFile);
            }
            if (directory != null) {
                Files.walk(directory)
                        .sorted(Comparator.reverseOrder())
                        .forEach(
                                path -> {
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
