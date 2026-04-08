/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.Environment;
import org.opensearch.secure_sm.AccessController;

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
import com.wazuh.contentmanager.cti.catalog.model.Cve;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.utils.Unzip;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Service responsible for handling the download, extraction, and indexing of CTI snapshots. It
 * extracts the contents of the payload and indexes them at the root.
 */
public class SnapshotServiceImpl implements SnapshotService {
    private static final Logger log = LogManager.getLogger(SnapshotServiceImpl.class);

    private final String context;
    private final String consumer;
    protected final Map<String, ContentIndex> indicesMap;
    private final ConsumersIndex consumersIndex;
    private SnapshotClient snapshotClient;
    private final Environment environment;
    private final PluginSettings pluginSettings;
    private final ObjectMapper mapper;

    /** The maximum offset encountered while processing snapshot files. */
    private long maxOffsetSeen;

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
        this.mapper = new ObjectMapper();

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
     * @return true if initialization was fully successful, false on failures.
     */
    @Override
    public boolean initialize(RemoteConsumer consumer) {
        String snapshotUrl = consumer.getSnapshotLink();

        if (snapshotUrl == null || snapshotUrl.isEmpty()) {
            log.warn("Snapshot URL is empty. Skipping initialization.");
            return false;
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
                return false;
            }

            // 2. Prepare output directory
            outputDir = this.environment.tmpDir().resolve("snapshot_" + System.currentTimeMillis());
            Files.createDirectories(outputDir);

            // 3. Unzip
            Unzip.unzip(snapshotZip, outputDir);

            // 4. Process and Index Files
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
            return false;
        } finally {
            // Cleanup temporary files
            this.cleanup(snapshotZip, outputDir);
        }

        // 6. Update Consumer State in .cti-consumers
        try {
            GetResponse getResponse = this.consumersIndex.getConsumer(this.context, this.consumer);
            LocalConsumer current =
                    (getResponse != null && getResponse.isExists())
                            ? this.mapper.readValue(getResponse.getSourceAsString(), LocalConsumer.class)
                            : new LocalConsumer(this.context, this.consumer);
            LocalConsumer updatedConsumer =
                    new LocalConsumer(
                            this.context,
                            this.consumer,
                            current.getStatus() != null ? current.getStatus() : LocalConsumer.Status.UPDATING,
                            consumer.getSnapshotOffset(),
                            consumer.getOffset(),
                            snapshotUrl);
            this.consumersIndex.setConsumer(updatedConsumer);
            return true;
        } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Failed to update consumer state in {}: {}", ConsumersIndex.INDEX_NAME, e.getMessage());
            return false;
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
        ContentIndex executorIndex =
                this.indicesMap.isEmpty() ? null : this.indicesMap.values().iterator().next();
        if (executorIndex == null) {
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(filePath, StandardCharsets.UTF_8)) {
            while ((line = reader.readLine()) != null) {
                try {
                    JsonNode rootJson = this.mapper.readTree(line);

                    // 1. Validate and Extract Payload
                    if (!rootJson.has(Constants.KEY_PAYLOAD)) {
                        log.warn("Snapshot entry missing '{}'. Skipping.", Constants.KEY_PAYLOAD);
                        continue;
                    }
                    JsonNode payload = rootJson.get(Constants.KEY_PAYLOAD);

                    // 2. Determine Index.
                    String resourceName =
                            rootJson.has(Constants.KEY_RESOURCE)
                                    ? rootJson.get(Constants.KEY_RESOURCE).asText()
                                    : (rootJson.has(Constants.KEY_NAME)
                                            ? rootJson.get(Constants.KEY_NAME).asText()
                                            : null);
                    String cveType = Cve.deriveType(resourceName);

                    String type = null;
                    if (cveType != null) {
                        // CVE feed entities are identified by the resource name pattern.
                        type = Constants.KEY_CVES;
                    } else if (payload.has(Constants.KEY_TYPE)) {
                        type = payload.get(Constants.KEY_TYPE).asText();
                        if (Constants.TYPE_IOC.equalsIgnoreCase(type)) {
                            type = Constants.KEY_IOCS;
                        }
                    }

                    if (type == null) {
                        log.warn("Could not identify resource type. Skipping.");
                        continue;
                    }

                    // 3. Select correct index based on type
                    ContentIndex indexHandler = this.indicesMap.get(type);
                    if (indexHandler == null) {
                        log.warn("No ContentIndex found for type [{}]. Skipping.", type);
                        continue;
                    }

                    // Inject the CTI offset value into the payload so it is persisted
                    if (rootJson.has(Constants.KEY_OFFSET) && payload.isObject()) {
                        long offset = rootJson.get(Constants.KEY_OFFSET).asLong();
                        ((ObjectNode) payload).put(Constants.KEY_OFFSET, offset);
                        this.maxOffsetSeen = Math.max(this.maxOffsetSeen, offset);
                    }

                    if (Constants.KEY_CVES.equals(type) && payload.isObject() && cveType != null) {
                        ((ObjectNode) payload).put(Constants.KEY_TYPE, cveType);
                    }

                    ObjectNode processedPayload = indexHandler.processPayload(payload);
                    String indexName = indexHandler.getIndexName();

                    // Create Index Request
                    IndexRequest indexRequest =
                            new IndexRequest(indexName).source(processedPayload.toString(), XContentType.JSON);

                    // Determine ID from resource/name key.
                    if (resourceName != null) {
                        indexRequest.id(resourceName);
                    } else {
                        throw new IOException(
                                "Missing 'resource'/'name' key in CTI resource. {offset}:"
                                        + rootJson.get("offset").asInt());
                    }

                    bulkRequest.add(indexRequest);
                    docCount++;

                    // Execute Bulk if limit reached
                    if (docCount >= this.pluginSettings.getMaxItemsPerBulk()) {
                        executorIndex.executeBulk(bulkRequest);
                        bulkRequest = new BulkRequest();
                        docCount = 0;
                    }

                } catch (IOException e) {
                    log.error("Error parsing/indexing JSON line: {}", e.getMessage());
                }
            }

            // Index remaining documents
            if (bulkRequest.numberOfActions() > 0) {
                executorIndex.executeBulk(bulkRequest);
            }

        } catch (Exception e) {
            log.error("Error reading snapshot file [{}]: {}", filePath, e.getMessage());
        }
    }

    /**
     * Returns the maximum offset encountered during the last snapshot file processing.
     *
     * @return the maximum offset value seen across all processed snapshot entries.
     */
    public long getMaxOffsetSeen() {
        return this.maxOffsetSeen;
    }

    /**
     * Initializes content from a pre-packaged local snapshot zip file. Unlike {@link
     * #initialize(RemoteConsumer)}, this method reads directly from a local file path instead of
     * downloading from a remote URL. After successful processing, the source zip file is permanently
     * deleted.
     *
     * @param localZip Path to the local snapshot zip file.
     * @return true if initialization was fully successful, false on failures.
     */
    @Override
    public boolean initialize(Path localZip) {
        log.info(
                "Starting local snapshot initialization for context [{}] consumer [{}] from [{}]",
                this.context,
                this.consumer,
                localZip);

        Path outputDir = null;
        this.maxOffsetSeen = 0;

        try {
            // 1. Prepare output directory
            outputDir = this.environment.tmpDir().resolve("snapshot_" + System.currentTimeMillis());
            Files.createDirectories(outputDir);

            // 2. Unzip local snapshot
            final Path extractDir = outputDir;
            AccessController.doPrivilegedChecked(
                    () -> {
                        Unzip.unzip(localZip, extractDir);
                        return null;
                    });

            // 3. Clear indices
            this.indicesMap.values().forEach(ContentIndex::clear);

            // 4. Process and Index Files
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
            log.error("Error processing local snapshot: {}", e.getMessage());
            return false;
        } finally {
            // Cleanup temporary extraction directory only
            this.cleanup(null, outputDir);
        }

        // 5. Delete source zip file
        try {
            AccessController.doPrivilegedChecked(
                    () -> {
                        Files.deleteIfExists(localZip);
                        return null;
                    });
            log.info("Deleted local snapshot file [{}]", localZip);
        } catch (Exception e) {
            log.warn("Failed to delete local snapshot file [{}]: {}", localZip, e.getMessage());
        }

        // 6. Update Consumer State in .cti-consumers
        try {
            GetResponse getResponse = this.consumersIndex.getConsumer(this.context, this.consumer);
            LocalConsumer current =
                    (getResponse != null && getResponse.isExists())
                            ? this.mapper.readValue(getResponse.getSourceAsString(), LocalConsumer.class)
                            : new LocalConsumer(this.context, this.consumer);
            LocalConsumer updatedConsumer =
                    new LocalConsumer(
                            this.context,
                            this.consumer,
                            current.getStatus() != null ? current.getStatus() : LocalConsumer.Status.UPDATING,
                            this.maxOffsetSeen,
                            0,
                            localZip.toString());
            this.consumersIndex.setConsumer(updatedConsumer);
            return true;
        } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Failed to update consumer state in {}: {}", ConsumersIndex.INDEX_NAME, e.getMessage());
            return false;
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
