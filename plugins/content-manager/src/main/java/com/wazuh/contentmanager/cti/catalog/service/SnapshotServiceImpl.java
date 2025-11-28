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
import com.wazuh.contentmanager.cti.catalog.client.SnapshotClient;
import com.wazuh.contentmanager.cti.catalog.index.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.utils.Unzip;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.Environment;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Service responsible for handling the download, extraction, and indexing of CTI snapshots.
 * It extracts the contents of the payload and indexes them at the root.
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
    private final List<ContentIndex> contentIndex;
    private final ConsumersIndex consumersIndex;
    private SnapshotClient snapshotClient;
    private final Environment environment;
    private final PluginSettings pluginSettings;

    public SnapshotServiceImpl(String context,
                               String consumer,
                               List<ContentIndex> contentIndex,
                               ConsumersIndex consumersIndex,
                               Environment environment) {
        this.context = context;
        this.consumer = consumer;
        this.contentIndex = contentIndex;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
        this.pluginSettings = PluginSettings.getInstance();

        this.snapshotClient = new SnapshotClient(this.environment);

    }

    /**
     * Used for testing. Inject mocks.
     *
     * @param client
     */
    public void setSnapshotClient(SnapshotClient client) {
        this.snapshotClient = client;
    }

    /**
     * Initializes the content by downloading the snapshot from the given link,
     * unzipping it, and indexing the content into specific indices.
     *
     * @param consumer information from the remote consumer. Contains the snapshot link from which the initialization takes place.
     */
    @Override
    public void initialize(RemoteConsumer consumer) {
        String snapshotUrl = consumer.getSnapshotLink();
        long offset = consumer.getOffset();

        if (snapshotUrl == null || snapshotUrl.isEmpty()) {
            log.warn("Snapshot URL is empty. Skipping initialization.");
            return;
        }

        log.info("Starting snapshot initialization for context [{}] consumer [{}]", this.context, this.consumer);
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
            this.contentIndex.forEach(ContentIndex::clear);

            // 5. Process and Index Files
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(outputDir, "*.json")) {
                for (Path entry : stream) {
                    this.processSnapshotFile(entry);
                }
            }
//        } catch (IOException | URISyntaxException e) {
        } catch (Exception e) {
            log.error("Error processing snapshot: {}", e.getMessage());
        } finally {
            // Cleanup temporary files
            this.cleanup(snapshotZip, outputDir);
        }

        // 6. Update Consumer State in .cti-consumers
        try {
            LocalConsumer updatedConsumer = new LocalConsumer(this.context, this.consumer, offset, offset, snapshotUrl);
            this.consumersIndex.setConsumer(updatedConsumer);
        } catch (Exception e) {
            log.error("Failed to update consumer state in {}: {}", ConsumersIndex.INDEX_NAME, e.getMessage());
        }
    }

    /**
     * Reads a JSON snapshot file line by line, extracts the contents of the payload object,
     * and indexes them directly at the root.
     *
     * @param filePath Path to the JSON file.
     */
    private void processSnapshotFile(Path filePath) {
        String line;
        int docCount = 0;
        BulkRequest bulkRequest = new BulkRequest();

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

                    // Skip policy type documents
                    if ("policy".equalsIgnoreCase(type)) {
                        log.debug("Skipping document with type {}.", type);
                        continue;
                    }

                    String indexName = this.getIndexName(type);

                    // 3. Extract the inner 'document' object for ID retrieval and Preprocessing
                    if (!payload.has(JSON_DOCUMENT_KEY)) {
                        log.warn("Payload missing '{}'. Skipping.", JSON_DOCUMENT_KEY);
                        continue;
                    }
                    JsonObject innerDocument = payload.getAsJsonObject(JSON_DOCUMENT_KEY);

                    // Preprocess the inner document
                    this.preprocessDocument(innerDocument);

                    // 4. Create Index Request
                    IndexRequest indexRequest = new IndexRequest(indexName)
                        .source(payload.toString(), XContentType.JSON);

                    if (innerDocument.has(JSON_ID_KEY)) {
                        indexRequest.id(innerDocument.get(JSON_ID_KEY).getAsString());
                    }

                    bulkRequest.add(indexRequest);
                    docCount++;

                    // Execute Bulk if limit reached
                    if (docCount >= this.pluginSettings.getMaxItemsPerBulk()) {
                        this.contentIndex.getFirst().executeBulk(bulkRequest);
                        bulkRequest = new BulkRequest();
                        docCount = 0;
                    }

                } catch (Exception e) {
                    log.error("Error parsing/indexing JSON line: {}", e.getMessage());
                }
            }

            // Index remaining documents
            if (bulkRequest.numberOfActions() > 0) {
                this.contentIndex.getFirst().executeBulk(bulkRequest);
            }

        } catch (IOException e) {
            log.error("Error reading snapshot file [{}]: {}", filePath, e.getMessage());
        }
    }

    private String getIndexName(String type) {
        return String.format(Locale.ROOT, ".%s-%s-%s", this.context, this.consumer, type);
    }

    /**
     * Preprocesses the document to handle field transformations.
     * Specifically, renames 'related.sigma_id' to 'related.id' to avoid StrictDynamicMappingException.
     *
     * @param document The document object to process.
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
     * Deletes temporary files and directories used during the process.
     */
    private void cleanup(Path zipFile, Path directory) {
        try {
            if (zipFile != null) Files.deleteIfExists(zipFile);
            if (directory != null) {
                Files.walk(directory)
                    .sorted(Comparator.reverseOrder())
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
