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

import com.wazuh.contentmanager.cti.catalog.client.RegularUrlResolver;
import com.wazuh.contentmanager.cti.catalog.client.ResourceUrlResolver;
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

    private final String consumerType;
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
     * @param consumerType The consumer type identifier used as local document id.
     * @param indicesMap A map of content types to their corresponding ContentIndex.
     * @param consumersIndex The consumers index to update consumer state.
     * @param environment The OpenSearch environment.
     * @param urlResolver The resolver used to transform resource URLs before making HTTP requests.
     */
    public SnapshotServiceImpl(
            String consumerType,
            Map<String, ContentIndex> indicesMap,
            ConsumersIndex consumersIndex,
            Environment environment,
            ResourceUrlResolver urlResolver) {
        this.consumerType = consumerType;
        this.indicesMap = indicesMap;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
        this.pluginSettings = PluginSettings.getInstance();
        this.mapper = new ObjectMapper();

        this.snapshotClient = new SnapshotClient(this.environment, urlResolver);
    }

    /**
     * Constructs a new SnapshotServiceImpl with an regular URL resolver.
     *
     * @param consumerType The consumer type identifier used as local document id.
     * @param indicesMap A map of content types to their corresponding ContentIndex.
     * @param consumersIndex The consumers index to update consumer state.
     * @param environment The OpenSearch environment.
     */
    public SnapshotServiceImpl(
            String consumerType,
            Map<String, ContentIndex> indicesMap,
            ConsumersIndex consumersIndex,
            Environment environment) {
        this(consumerType, indicesMap, consumersIndex, environment, new RegularUrlResolver());
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
            log.warn(Constants.W_LOG_SNAPSHOT_URL_EMPTY);
            return false;
        }

        log.debug(Constants.D_LOG_SNAPSHOT_INIT_START, this.consumerType);
        Path snapshotZip = null;
        Path outputDir = null;

        try {
            // 1. Download Snapshot
            snapshotZip = this.snapshotClient.downloadFile(snapshotUrl);
            if (snapshotZip == null) {
                log.error(Constants.E_LOG_SNAPSHOT_DOWNLOAD_FAILED, snapshotUrl);
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
                log.debug(Constants.D_LOG_SNAPSHOT_WAIT_PENDING_BULK);
                this.indicesMap.values().iterator().next().waitForPendingUpdates();
            }

        } catch (Exception e) {
            log.error(Constants.E_LOG_SNAPSHOT_PROCESS_FAILED, e.getMessage());
            return false;
        } finally {
            // Cleanup temporary files
            this.cleanup(snapshotZip, outputDir);
        }

        // 5. Partial update of consumer state: bump local_offset to the snapshot offset and keep
        // the remote_offset (set at t0 from RemoteConsumer.last_offset) so the incremental update
        // path can close the gap. Identity fields and status are preserved from the t0 write.
        return this.updateLocalOffset(consumer.getSnapshotOffset());
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
        int missingPayload = 0;
        int unknownType = 0;
        int unmappedType = 0;
        int parseErrors = 0;
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
                        missingPayload++;
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
                        unknownType++;
                        continue;
                    }

                    // 3. Select correct index based on type
                    ContentIndex indexHandler = this.indicesMap.get(type);
                    if (indexHandler == null) {
                        log.debug(Constants.D_LOG_SNAPSHOT_NO_INDEX_FOR_TYPE, type);
                        unmappedType++;
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
                    String writeIndex = indexHandler.getWriteIndex();

                    // Create Index Request
                    IndexRequest indexRequest =
                            new IndexRequest(writeIndex).source(processedPayload.toString(), XContentType.JSON);

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

                    // Flush when EITHER the document count OR the estimated byte size cap is reached.
                    // estimatedSizeInBytes() is maintained incrementally by BulkRequest.add(...), so
                    // this adds no per-doc work. The byte trigger bounds per-request heap regardless
                    // of individual document size (e.g. large CVE documents); the count trigger still
                    // governs small docs. Worst-case in-flight heap = MAX_CONCURRENT_BULKS *
                    // MAX_BULK_BYTES.
                    if (docCount >= this.pluginSettings.getMaxItemsPerBulk()
                            || bulkRequest.estimatedSizeInBytes() >= this.pluginSettings.getMaxBulkBytes()) {
                        executorIndex.executeBulk(bulkRequest);
                        bulkRequest = new BulkRequest();
                        docCount = 0;
                    }

                } catch (IOException e) {
                    log.debug(Constants.D_LOG_SNAPSHOT_PARSE_LINE_FAILED, e.getMessage());
                    parseErrors++;
                }
            }

            int skipped = missingPayload + unknownType + unmappedType + parseErrors;
            if (skipped > 0) {
                log.warn(
                        Constants.W_LOG_SNAPSHOT_ENTRIES_SKIPPED,
                        skipped,
                        missingPayload,
                        unknownType,
                        unmappedType,
                        parseErrors);
            }

            // Index remaining documents
            if (bulkRequest.numberOfActions() > 0) {
                executorIndex.executeBulk(bulkRequest);
            }

        } catch (Exception e) {
            log.error(Constants.E_LOG_SNAPSHOT_READ_FILE_FAILED, filePath, e.getMessage());
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
     * Initializes content from a pre-packaged local snapshot zip file using consumer metadata from
     * the external {@code manifest.json} located in the snapshots' directory.
     *
     * <p>The {@code manifestEntry} is the JSON object keyed by the snapshot filename in the shared
     * manifest (e.g., the value for {@code "ruleset.zip"}). When {@code null}, field defaults are
     * taken from the service's constructor arguments.
     *
     * <p>After successful processing, the source zip file is permanently deleted.
     *
     * @param localZip The path to the local snapshot zip file.
     * @param manifestEntry The consumer metadata node from the external manifest, or {@code null}.
     * @return true if initialization was fully successful, false on failures.
     */
    @Override
    public boolean initialize(Path localZip, JsonNode manifestEntry) {
        log.debug(Constants.D_LOG_SNAPSHOT_LOCAL_INIT_START, this.consumerType, localZip.getFileName());

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
                log.debug(Constants.D_LOG_SNAPSHOT_WAIT_PENDING_BULK);
                this.indicesMap.values().iterator().next().waitForPendingUpdates();
            }

        } catch (Exception e) {
            log.error(Constants.E_LOG_SNAPSHOT_LOCAL_PROCESS_FAILED, e.getMessage());
            return false;
        } finally {
            // Cleanup temporary extraction directory only
            this.cleanup(null, outputDir);
        }

        // 5. Delete source zip file
        SnapshotServiceImpl.deleteSnapshot(localZip);

        // 6. Partial update of consumer state: bump local_offset to the highest offset observed
        // while indexing. Identity fields, is_public, status and remote_offset are owned by the
        // t0 write performed by AbstractConsumerService.writeInitialConsumer.
        return this.updateLocalOffset(this.maxOffsetSeen);
    }

    /**
     * Reads the existing consumer document and persists it back with only {@code local_offset}
     * mutated. All other fields (identity, {@code is_public}, {@code status}, {@code remote_offset})
     * are preserved. Returns {@code false} and logs a warning if no document exists — the t0 write in
     * {@link AbstractConsumerService} is expected to create it before this method runs.
     */
    private boolean updateLocalOffset(long newLocalOffset) {
        try {
            GetResponse getResponse = this.consumersIndex.getConsumer(this.consumerType);
            if (getResponse == null || !getResponse.isExists()) {
                log.warn(Constants.W_LOG_SNAPSHOT_CONSUMER_DOC_MISSING, this.consumerType);
                return false;
            }
            LocalConsumer current =
                    this.mapper.readValue(getResponse.getSourceAsString(), LocalConsumer.class);
            LocalConsumer updatedConsumer =
                    new LocalConsumer(
                            current.getContext(),
                            current.getName(),
                            current.getType(),
                            current.getResource(),
                            current.isPublic(),
                            current.getStatus() != null ? current.getStatus() : LocalConsumer.Status.RUNNING,
                            newLocalOffset,
                            current.getRemoteOffset());
            this.consumersIndex.setConsumer(updatedConsumer);
            return true;
        } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    Constants.E_LOG_SNAPSHOT_CONSUMER_STATE_UPDATE_FAILED,
                    ConsumersIndex.INDEX_NAME,
                    e.getMessage());
            return false;
        }
    }

    /**
     * Deletes a local snapshot zip file. Logs success at info level and failures at warn level. Safe
     * to call when the file does not exist. Only files under the plugin's local snapshots directory
     * should be passed in — remote snapshots are managed by the CTI service.
     *
     * @param snapshot The path to the local snapshot file to delete.
     */
    public static void deleteSnapshot(Path snapshot) {
        try {
            boolean deleted = AccessController.doPrivilegedChecked(() -> Files.deleteIfExists(snapshot));
            if (deleted) {
                log.debug(Constants.D_LOG_SNAPSHOT_LOCAL_DELETED, snapshot);
            }
        } catch (Exception e) {
            log.warn(Constants.W_LOG_SNAPSHOT_LOCAL_DELETE_FAILED, snapshot, e.getMessage());
        }
    }

    /**
     * Deletes every local snapshot zip file found directly under the given snapshots directory,
     * delegating each deletion to {@link #deleteSnapshot(Path)}. Safe to call when the directory does
     * not exist (e.g. development environments). Only the plugin's local snapshots directory should
     * be passed in — remote snapshots are managed by the CTI service.
     *
     * @param snapshotsDir The plugin's local snapshots directory.
     */
    public static void deleteSnapshots(Path snapshotsDir) {
        try {
            AccessController.doPrivilegedChecked(
                    () -> {
                        if (!Files.isDirectory(snapshotsDir)) {
                            return null;
                        }
                        try (DirectoryStream<Path> stream = Files.newDirectoryStream(snapshotsDir, "*.zip")) {
                            for (Path snapshot : stream) {
                                deleteSnapshot(snapshot);
                            }
                        }
                        return null;
                    });
        } catch (Exception e) {
            log.warn("Failed to delete local snapshots in [{}]: {}", snapshotsDir, e.getMessage());
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
                                        log.warn(Constants.W_LOG_SNAPSHOT_TEMP_FILE_DELETE_FAILED, path);
                                    }
                                });
            }
        } catch (IOException e) {
            log.warn(Constants.W_LOG_SNAPSHOT_CLEANUP_FAILED, e.getMessage());
        }
    }
}
