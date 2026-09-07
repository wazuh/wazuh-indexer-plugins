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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
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
import java.net.URI;
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
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Service responsible for handling the download and indexing of CTI snapshots. Snapshot entries are
 * read directly from the ZIP file using streaming — no intermediate extraction to disk.
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
    private final Path stablePath;

    private static final int FLUSH_EVERY_N_BULKS = 10;

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
     * @param snapshotsDir The plugin's local snapshots directory, or {@code null} when stable
     *     snapshot retention is not needed (e.g. shadow swap, tests).
     * @param snapshotFilename The consumer's snapshot filename (e.g. "ruleset.zip"), or {@code null}.
     */
    public SnapshotServiceImpl(
            String consumerType,
            Map<String, ContentIndex> indicesMap,
            ConsumersIndex consumersIndex,
            Environment environment,
            ResourceUrlResolver urlResolver,
            Path snapshotsDir,
            String snapshotFilename) {
        this.consumerType = consumerType;
        this.indicesMap = indicesMap;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
        this.pluginSettings = PluginSettings.getInstance();
        this.mapper = new ObjectMapper();
        this.snapshotClient = new SnapshotClient(this.environment, urlResolver);

        if (snapshotsDir != null && snapshotFilename != null) {
            String stableFilename = snapshotFilename.replace(".zip", Constants.STABLE_SNAPSHOT_SUFFIX);
            this.stablePath = snapshotsDir.resolve(stableFilename);
        } else {
            this.stablePath = null;
        }
    }

    /**
     * Constructs a new SnapshotServiceImpl without stable snapshot retention.
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
        this(consumerType, indicesMap, consumersIndex, environment, urlResolver, null, null);
    }

    /**
     * Constructs a new SnapshotServiceImpl with a regular URL resolver and no stable snapshot
     * retention.
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
     * Initializes the content by downloading the snapshot from the given link and streaming its JSON
     * entries directly from the ZIP file without extracting to disk.
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
        long startMs = 0;
        boolean success = false;

        try {
            this.resetDroppedDocuments();

            // 1. Download Snapshot
            snapshotZip = this.snapshotClient.downloadFile(snapshotUrl);
            if (snapshotZip == null) {
                log.error(Constants.E_LOG_SNAPSHOT_DOWNLOAD_FAILED, snapshotUrl);
                return false;
            }

            // 2. Stream and index JSON entries directly from the ZIP
            startMs = System.currentTimeMillis();
            this.processZip(snapshotZip);

            // Ensure all bulk requests are finished
            if (!this.indicesMap.isEmpty()) {
                log.debug(Constants.D_LOG_SNAPSHOT_WAIT_PENDING_BULK);
                this.indicesMap.values().iterator().next().waitForPendingUpdates();
            }

            success = true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error(Constants.E_LOG_SNAPSHOT_PROCESS_FAILED, e.getMessage());
        } catch (Exception e) {
            log.error(Constants.E_LOG_SNAPSHOT_PROCESS_FAILED, e.getMessage());
        }

        if (success) {
            if (startMs != 0) {
                log.debug(
                        Constants.D_LOG_SNAPSHOT_ELAPSED,
                        snapshotZip.getFileName(),
                        System.currentTimeMillis() - startMs);
            }

            // 3. Refuse to commit a partial load, before touching stable or the offset. A dropped
            // document means the snapshot did not index in full, so it must neither advance
            // local_offset (the next sync would skip the gap) nor be promoted to stable: "stable"
            // means a snapshot indexed in full at least once, and promoting a partial load would
            // overwrite a good safety net with one the rollback path has just proven unloadable.
            // Discarding the temp keeps any previously-good stable in place.
            long dropped = this.getDroppedDocuments();
            if (dropped > 0) {
                log.error(Constants.E_LOG_SNAPSHOT_INDEXING_INCOMPLETE, this.consumerType, dropped);
                this.cleanup(snapshotZip);
                return false;
            }

            // 4. Promote to stable or clean up temp
            if (this.stablePath != null) {
                if (!promoteToStable(snapshotZip, this.stablePath)) {
                    this.cleanup(snapshotZip);
                }
            } else {
                this.cleanup(snapshotZip);
            }

            // 5. Partial update of consumer state: bump local_offset to the snapshot offset and
            // keep the remote_offset (set at t0 from RemoteConsumer.last_offset) so the
            // incremental update path can close the gap. Identity fields and status are preserved
            // from the t0 write.
            return this.updateLocalOffset(consumer.getSnapshotOffset());
        } else {
            this.cleanup(snapshotZip);
            return false;
        }
    }

    /**
     * Mounts the ZIP as a {@link FileSystem} via the JDK's built-in {@code ZipFileSystem} provider
     * (which reads the central directory and correctly handles ZIP64 archives), then processes every
     * {@code *.json} entry by reading it as NDJSON and bulk-indexing the documents.
     *
     * @param zipPath path to the ZIP file to process.
     * @throws IOException if the ZIP file cannot be opened or read.
     */
    private void processZip(Path zipPath) throws IOException {
        URI uri = URI.create("jar:" + zipPath.toUri());
        try (FileSystem zipFs = FileSystems.newFileSystem(uri, Collections.emptyMap())) {
            for (Path root : zipFs.getRootDirectories()) {
                try (DirectoryStream<Path> entries = Files.newDirectoryStream(root, "*.json")) {
                    for (Path entry : entries) {
                        this.processZipEntry(entry);
                    }
                }
            }
        }
    }

    /**
     * Reads a single ZIP entry path as NDJSON, extracts the payload from each line, and bulk-indexes
     * the documents into the appropriate content index.
     *
     * @param entryPath the {@link Path} to the entry inside the ZIP {@link FileSystem}.
     * @throws IOException if the entry stream cannot be opened.
     */
    private void processZipEntry(Path entryPath) throws IOException {
        String line;
        int docCount = 0;
        int bulkCount = 0;
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

        try (BufferedReader reader = Files.newBufferedReader(entryPath, StandardCharsets.UTF_8)) {
            while ((line = reader.readLine()) != null) {
                try {
                    LazyEnvelope envelope = this.parseLazyEnvelope(line);

                    if (!envelope.hasPayload || envelope.resourceName == null) {
                        missingPayload++;
                        continue;
                    }

                    String cveType = Cve.deriveType(envelope.resourceName);

                    String type = null;
                    if (cveType != null) {
                        type = Constants.KEY_CVES;
                    } else if (envelope.type != null) {
                        type = envelope.type;
                        if (Constants.TYPE_IOC.equalsIgnoreCase(type)) {
                            type = Constants.KEY_IOCS;
                        }
                    }

                    if (type == null) {
                        unknownType++;
                        continue;
                    }

                    ContentIndex indexHandler = this.indicesMap.get(type);
                    if (indexHandler == null) {
                        log.debug(Constants.D_LOG_SNAPSHOT_NO_INDEX_FOR_TYPE, type);
                        unmappedType++;
                        continue;
                    }

                    if (envelope.hasOffset) {
                        this.maxOffsetSeen = Math.max(this.maxOffsetSeen, envelope.offset);
                    }

                    String sourceJson;
                    if (Constants.KEY_CVES.equals(type) && cveType != null && envelope.documentRaw != null) {
                        sourceJson = envelope.toCveStoredDocument(cveType);
                    } else {
                        ObjectNode syntheticPayload = envelope.toPayloadNode(this.mapper);
                        if (Constants.KEY_CVES.equals(type) && cveType != null) {
                            syntheticPayload.put(Constants.KEY_TYPE, cveType);
                        }
                        sourceJson = indexHandler.processPayloadToString(syntheticPayload);
                    }

                    IndexRequest indexRequest =
                            new IndexRequest(indexHandler.getWriteIndex())
                                    .source(sourceJson, XContentType.JSON)
                                    .id(envelope.resourceName);

                    bulkRequest.add(indexRequest);
                    envelope = null;
                    docCount++;

                    if (docCount >= this.pluginSettings.getMaxItemsPerBulk()
                            || bulkRequest.estimatedSizeInBytes() >= this.pluginSettings.getMaxBulkBytes()) {
                        executorIndex.executeBulk(bulkRequest);
                        bulkRequest = new BulkRequest();
                        docCount = 0;
                        bulkCount++;

                        if (bulkCount % FLUSH_EVERY_N_BULKS == 0) {
                            try {
                                executorIndex.waitForPendingUpdates();
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                throw new IOException("Interrupted while waiting for pending bulks", e);
                            }
                            executorIndex.flush();
                        }
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

    /** Clears the dropped-document counters before a load, so the tally covers this run only. */
    private void resetDroppedDocuments() {
        this.indicesMap.values().forEach(ContentIndex::resetDroppedDocuments);
    }

    /**
     * Total documents the content indices gave up on during this load. A non-zero value means the
     * snapshot is only partially indexed, so the consumer offset must not be advanced over the gap:
     * incremental syncs resume from the offset and would never backfill the missing documents.
     *
     * @return the number of dropped documents across all content indices.
     */
    private long getDroppedDocuments() {
        return this.indicesMap.values().stream().mapToLong(ContentIndex::getDroppedDocuments).sum();
    }

    /**
     * Initializes content from a pre-packaged local snapshot zip file using consumer metadata from
     * the external {@code manifest.json} located in the snapshots' directory.
     *
     * <p>The {@code manifestEntry} is the JSON object keyed by the snapshot filename in the shared
     * manifest (e.g., the value for {@code "ruleset.zip"}). When {@code null}, field defaults are
     * taken from the service's constructor arguments.
     *
     * <p>JSON entries are streamed directly from the ZIP — no extraction to disk. After successful
     * processing, the source zip file is permanently deleted.
     *
     * @param localZip The path to the local snapshot zip file.
     * @param manifestEntry The consumer metadata node from the external manifest, or {@code null}.
     * @return true if initialization was fully successful, false on failures.
     */
    @Override
    public boolean initialize(Path localZip, JsonNode manifestEntry) {
        log.debug(Constants.D_LOG_SNAPSHOT_LOCAL_INIT_START, this.consumerType, localZip.getFileName());

        this.maxOffsetSeen = 0;
        long startMs = System.currentTimeMillis();

        try {
            this.resetDroppedDocuments();

            // 1. Clear indices
            this.indicesMap.values().forEach(ContentIndex::clear);

            // 2. Stream and index JSON entries directly from the ZIP
            AccessController.doPrivilegedChecked(
                    () -> {
                        this.processZip(localZip);
                        return null;
                    });

            // Ensure all bulk requests are finished
            if (!this.indicesMap.isEmpty()) {
                log.debug(Constants.D_LOG_SNAPSHOT_WAIT_PENDING_BULK);
                this.indicesMap.values().iterator().next().waitForPendingUpdates();
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error(Constants.E_LOG_SNAPSHOT_LOCAL_PROCESS_FAILED, e.getMessage());
            return false;
        } catch (Exception e) {
            log.error(Constants.E_LOG_SNAPSHOT_LOCAL_PROCESS_FAILED, e.getMessage());
            return false;
        }

        log.debug(
                Constants.D_LOG_SNAPSHOT_LOCAL_ELAPSED,
                localZip.getFileName(),
                System.currentTimeMillis() - startMs);

        // 3. Refuse to commit a partial load, before touching stable or the offset. A dropped
        // document means the snapshot did not index in full, so it must neither advance
        // local_offset (the next sync would skip the gap) nor be promoted to stable. Returning
        // here also leaves the source in place: a rollback reload (localZip == stablePath) keeps
        // the stable untouched, and a packaged snapshot stays available for the next retry
        // instead of overwriting a good stable with a load proven unable to index in full.
        long dropped = this.getDroppedDocuments();
        if (dropped > 0) {
            log.error(Constants.E_LOG_SNAPSHOT_INDEXING_INCOMPLETE, this.consumerType, dropped);
            return false;
        }

        // 4. Promote to stable, delete source, or leave in place (rollback re-index)
        if (this.stablePath != null && !localZip.equals(this.stablePath)) {
            promoteToStable(localZip, this.stablePath);
        } else if (this.stablePath == null) {
            SnapshotServiceImpl.deleteSnapshot(localZip);
        }

        // 5. Partial update of consumer state: bump local_offset to the highest offset observed
        // while indexing. Identity fields, is_public, status and remote_offset are owned by the
        // t0 write performed by AbstractConsumerService.writeInitialConsumer.
        return this.updateLocalOffset(this.maxOffsetSeen);
    }

    /**
     * Reads the existing consumer document and persists it back with only {@code local_offset}
     * mutated. All other fields (identity, {@code is_public}, {@code status}, {@code remote_offset},
     * {@code pending_sync_phases}) are preserved. Returns {@code false} and logs a warning if no
     * document exists — the t0 write in {@link AbstractConsumerService} is expected to create it
     * before this method runs.
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
                            current.getRemoteOffset(),
                            current.getPendingSyncPhases());
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
     * Moves the candidate snapshot to the stable path, replacing any existing stable file. Uses
     * atomic move when possible, falling back to copy-then-delete for cross-filesystem scenarios.
     *
     * @param candidate the path of the successfully-indexed snapshot.
     * @param stablePath the target stable path.
     * @return {@code true} if the promotion succeeded, {@code false} on any I/O error.
     */
    public static boolean promoteToStable(Path candidate, Path stablePath) {
        try {
            AccessController.doPrivilegedChecked(
                    () -> {
                        try {
                            Files.move(
                                    candidate,
                                    stablePath,
                                    StandardCopyOption.REPLACE_EXISTING,
                                    StandardCopyOption.ATOMIC_MOVE);
                        } catch (AtomicMoveNotSupportedException e) {
                            Files.copy(candidate, stablePath, StandardCopyOption.REPLACE_EXISTING);
                            Files.deleteIfExists(candidate);
                        }
                        return null;
                    });
            log.debug(Constants.D_LOG_SNAPSHOT_PROMOTED_TO_STABLE, stablePath);
            return true;
        } catch (Exception e) {
            log.warn(Constants.W_LOG_SNAPSHOT_PROMOTE_FAILED, stablePath, e.getMessage());
            return false;
        }
    }

    /**
     * Returns the path to the stable snapshot, or {@code null} if stable snapshot retention is not
     * configured for this instance.
     */
    public Path getStablePath() {
        return this.stablePath;
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
                                String name = snapshot.getFileName().toString();
                                if (!name.endsWith(Constants.STABLE_SNAPSHOT_SUFFIX)) {
                                    deleteSnapshot(snapshot);
                                }
                            }
                        }
                        return null;
                    });
        } catch (Exception e) {
            log.warn("Failed to delete local snapshots in [{}]: {}", snapshotsDir, e.getMessage());
        }
    }

    /** Deletes the downloaded snapshot ZIP from the temporary directory. */
    private void cleanup(Path zipFile) {
        try {
            if (zipFile != null) {
                Files.deleteIfExists(zipFile);
            }
        } catch (IOException e) {
            log.warn(Constants.W_LOG_SNAPSHOT_CLEANUP_FAILED, e.getMessage());
        }
    }

    /**
     * Result of a lazy/partial NDJSON envelope parse. Holds routing-level fields as primitives and
     * the deep payload document content as a raw JSON string. The full Jackson tree is only
     * materialized on demand via {@link #getDocumentNode}.
     */
    static final class LazyEnvelope {
        String resourceName;
        long offset;
        boolean hasOffset;
        boolean hasPayload;

        String type;
        String spaceName;
        String documentRaw;
        boolean documentIsPayload;

        private ObjectNode documentNode;

        /**
         * Returns the document as an ObjectNode, lazily parsing {@link #documentRaw} on first call. The
         * result is cached and returned on subsequent calls, so callers must not mutate it if they
         * intend to call this method again.
         */
        ObjectNode getDocumentNode(ObjectMapper mapper) throws IOException {
            if (this.documentNode == null && this.documentRaw != null) {
                JsonNode parsed = mapper.readTree(this.documentRaw);
                if (parsed.isObject()) {
                    this.documentNode = (ObjectNode) parsed;
                }
            }
            return this.documentNode;
        }

        /**
         * Constructs the synthetic payload ObjectNode that {@link ContentIndex#processPayload} expects,
         * using the streamed primitives and the lazily parsed document node. Only the document portion
         * is parsed from raw JSON; the routing fields are set directly.
         */
        ObjectNode toPayloadNode(ObjectMapper mapper) throws IOException {
            ObjectNode payload = mapper.createObjectNode();
            if (this.hasOffset) {
                payload.put(Constants.KEY_OFFSET, this.offset);
            }
            if (this.type != null) {
                payload.put(Constants.KEY_TYPE, this.type);
            }
            ObjectNode docNode = this.getDocumentNode(mapper);
            if (docNode != null) {
                payload.set(Constants.KEY_DOCUMENT, docNode);
            }
            if (this.spaceName != null) {
                ObjectNode space = mapper.createObjectNode();
                space.put(Constants.KEY_NAME, this.spaceName);
                payload.set(Constants.KEY_SPACE, space);
            }
            return payload;
        }

        /**
         * Builds the stored document JSON for CVE fast-path types via StringBuilder, matching the shape
         * produced by the full-tree CVE pipeline without materializing a tree.
         */
        String toCveStoredDocument(String cveType) {
            StringBuilder sb =
                    new StringBuilder((this.documentRaw != null ? this.documentRaw.length() : 0) + 64);
            sb.append("{\"").append(Constants.KEY_DOCUMENT).append("\":");
            sb.append(this.documentRaw);
            if (this.hasOffset) {
                sb.append(",\"").append(Constants.KEY_OFFSET).append("\":").append(this.offset);
            }
            sb.append(",\"").append(Constants.KEY_TYPE).append("\":\"").append(cveType).append("\"}");
            return sb.toString();
        }
    }

    /**
     * Lazy/partial parse of a single NDJSON envelope line.
     *
     * <p>Walks the token stream once, extracting envelope-level fields ({@code resource}, {@code
     * name}, {@code offset}) as primitives, then descends into the {@code payload} object to stream
     * routing fields ({@code type}, {@code space.name}) and capture the {@code document} value as a
     * raw JSON string. No full Jackson tree is built for the line or the payload wrapper.
     *
     * @param line The raw NDJSON line.
     * @return The extracted {@link LazyEnvelope}. {@code hasPayload} is {@code false} when the line
     *     is not a JSON object or carries no {@code payload} field.
     * @throws IOException If the line is not well-formed JSON.
     */
    LazyEnvelope parseLazyEnvelope(String line) throws IOException {
        LazyEnvelope env = new LazyEnvelope();
        String resource = null;
        String name = null;

        try (JsonParser parser = this.mapper.getFactory().createParser(line)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return env;
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String field = parser.currentName();
                JsonToken value = parser.nextToken();
                if (field == null) {
                    return env;
                }
                switch (field) {
                    case Constants.KEY_RESOURCE:
                        resource = parser.getValueAsString();
                        break;
                    case Constants.KEY_NAME:
                        name = parser.getValueAsString();
                        break;
                    case Constants.KEY_OFFSET:
                        if (value != null && value.isNumeric()) {
                            env.offset = parser.getLongValue();
                            env.hasOffset = true;
                        }
                        break;
                    case Constants.KEY_PAYLOAD:
                        if (value == JsonToken.START_OBJECT) {
                            env.hasPayload = true;
                            this.parsePayloadFields(parser, line, env);
                        } else {
                            parser.skipChildren();
                        }
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }

        env.resourceName = resource != null ? resource : name;
        return env;
    }

    /**
     * Descends into the {@code payload} object and streams its top-level routing fields, capturing
     * the {@code document} value as raw JSON text via character-offset slicing.
     */
    private void parsePayloadFields(JsonParser parser, String line, LazyEnvelope env)
            throws IOException {
        long payloadStart = parser.currentTokenLocation().getCharOffset();
        boolean hasDocumentKey = false;
        boolean hasNonDocumentStructural = false;
        String legacyRaw = null;

        while (parser.nextToken() != JsonToken.END_OBJECT) {
            String field = parser.currentName();
            JsonToken value = parser.nextToken();

            if (field == null) {
                break;
            }

            switch (field) {
                case Constants.KEY_TYPE:
                    env.type = parser.getValueAsString();
                    hasNonDocumentStructural = true;
                    break;
                case Constants.KEY_DOCUMENT:
                    if (value == JsonToken.START_OBJECT || value == JsonToken.START_ARRAY) {
                        env.documentRaw = this.sliceCurrentValue(parser, line);
                        hasDocumentKey = true;
                    } else {
                        parser.skipChildren();
                    }
                    break;
                case Constants.KEY_PAYLOAD:
                    if (value == JsonToken.START_OBJECT || value == JsonToken.START_ARRAY) {
                        legacyRaw = this.sliceCurrentValue(parser, line);
                    } else {
                        parser.skipChildren();
                    }
                    break;
                case Constants.KEY_SPACE:
                    if (value == JsonToken.START_OBJECT) {
                        while (parser.nextToken() != JsonToken.END_OBJECT) {
                            String spaceField = parser.currentName();
                            parser.nextToken();
                            if (Constants.KEY_NAME.equals(spaceField)) {
                                env.spaceName = parser.getValueAsString();
                            } else {
                                parser.skipChildren();
                            }
                        }
                    } else {
                        parser.skipChildren();
                    }
                    break;
                case Constants.KEY_OFFSET:
                    hasNonDocumentStructural = true;
                    parser.skipChildren();
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }

        if (!hasDocumentKey && legacyRaw != null) {
            env.documentRaw = legacyRaw;
        } else if (!hasDocumentKey && !hasNonDocumentStructural) {
            long payloadEnd = parser.currentLocation().getCharOffset();
            if (payloadStart >= 0 && payloadEnd > payloadStart && payloadEnd <= line.length()) {
                env.documentRaw = line.substring((int) payloadStart, (int) payloadEnd);
                env.documentIsPayload = true;
            }
        }
    }

    /**
     * Slices the raw JSON text of the value the parser is currently positioned on, consuming the
     * whole subtree with. Returns {@code null} if the computed offsets are not usable.
     */
    private String sliceCurrentValue(JsonParser parser, String line) throws IOException {
        long start = parser.currentTokenLocation().getCharOffset();
        parser.skipChildren();
        long end = parser.currentLocation().getCharOffset();
        if (start < 0 || end < start || end > line.length()) {
            return null;
        }
        return line.substring((int) start, (int) end);
    }
}
