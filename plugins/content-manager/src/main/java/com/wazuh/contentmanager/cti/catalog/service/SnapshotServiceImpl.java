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

import com.fasterxml.jackson.core.JsonFactory;
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

    /**
     * Raw passthrough is only sound when nothing downstream depends on a transformed document:
     * currently just the CVE/vulnerabilities consumer. The ruleset and IoC consumers require their
     * transforms, so they never pass through raw.
     */
    private final boolean rawDocumentPassthrough;

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
        this.rawDocumentPassthrough = Constants.CONSUMER_TYPE_VULNERABILITIES.equals(consumerType);

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
            // Promote to stable or clean up temp
            if (this.stablePath != null) {
                if (!promoteToStable(snapshotZip, this.stablePath)) {
                    this.cleanup(snapshotZip);
                }
            } else {
                this.cleanup(snapshotZip);
            }
            // 3. Partial update of consumer state: bump local_offset to the snapshot offset and
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
    private static final int FLUSH_EVERY_N_BULKS = 10;

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
                    // Raw-passthrough fast path
                    if (this.rawDocumentPassthrough) {
                        LazyCveDocument lazy = this.parseLazyCve(line);
                        if (lazy != null) {
                            if (lazy.hasOffset) {
                                this.maxOffsetSeen = Math.max(this.maxOffsetSeen, lazy.offset);
                            }
                            IndexRequest indexRequest =
                                    new IndexRequest(executorIndex.getWriteIndex())
                                            .source(lazy.toStoredDocument(), XContentType.JSON)
                                            .id(lazy.id);
                            bulkRequest.add(indexRequest);
                            docCount++;

                            if (docCount >= this.pluginSettings.getMaxItemsPerBulk()
                                    || bulkRequest.estimatedSizeInBytes() >= this.pluginSettings.getMaxBulkBytes()) {
                                executorIndex.executeBulk(bulkRequest);
                                bulkRequest = new BulkRequest();
                                docCount = 0;
                            }
                            continue;
                        }
                    }

                    // Transform path
                    Envelope envelope = this.parseEnvelope(line);

                    // 1. Validate and Extract Payload
                    if (!envelope.hasPayload) {
                        missingPayload++;
                        continue;
                    }
                    JsonNode payload = envelope.payload;
                    String resourceName = envelope.resourceName;

                    // 2. Determine Index.
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
                    if (envelope.hasOffset && payload.isObject()) {
                        ((ObjectNode) payload).put(Constants.KEY_OFFSET, envelope.offset);
                        this.maxOffsetSeen = Math.max(this.maxOffsetSeen, envelope.offset);
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
                                "Missing 'resource'/'name' key in CTI resource. {offset}:" + envelope.offset);
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

        } catch (Exception e) {
            log.error(Constants.E_LOG_SNAPSHOT_LOCAL_PROCESS_FAILED, e.getMessage());
            return false;
        }

        // 3. Promote to stable, delete source, or leave in place (rollback re-index)
        if (this.stablePath != null && !localZip.equals(this.stablePath)) {
            promoteToStable(localZip, this.stablePath);
        } else if (this.stablePath == null) {
            SnapshotServiceImpl.deleteSnapshot(localZip);
        }

        log.debug(
                Constants.D_LOG_SNAPSHOT_LOCAL_ELAPSED,
                localZip.getFileName(),
                System.currentTimeMillis() - startMs);

        // 4. Partial update of consumer state: bump local_offset to the highest offset observed
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
     * Result of a lazy/partial CVE envelope parse. Holds only the envelope fields needed to build the
     * stored document; the deep payload stays as the raw {@link #documentRaw} string.
     */
    static final class LazyCveDocument {
        final String id;
        final long offset;
        final boolean hasOffset;
        private final String type;
        private final String documentRaw;

        private LazyCveDocument(
                String id, long offset, boolean hasOffset, String type, String documentRaw) {
            this.id = id;
            this.offset = offset;
            this.hasOffset = hasOffset;
            this.type = type;
            this.documentRaw = documentRaw;
        }

        /**
         * Builds the stored document JSON string, matching the shape produced by the full-tree CVE
         * pipeline ({@code {"document": …, "offset": …, "type": …}}) without re-serializing the deep
         * payload.
         *
         * @return The stored document as a compact JSON string.
         */
        String toStoredDocument() {
            StringBuilder sb = new StringBuilder(this.documentRaw.length() + 48);
            sb.append("{\"").append(Constants.KEY_DOCUMENT).append("\":").append(this.documentRaw);
            if (this.hasOffset) {
                sb.append(",\"").append(Constants.KEY_OFFSET).append("\":").append(this.offset);
            }
            sb.append(",\"").append(Constants.KEY_TYPE).append("\":\"").append(this.type).append("\"}");
            return sb.toString();
        }
    }

    /**
     * Lazy/partial parse of a single CVE NDJSON envelope line
     *
     * <p>Instead of materializing the whole envelope into a Jackson {@code JsonNode} tree (as {@code
     * ObjectMapper.readTree} does), this walks the token stream once and captures only the top-level
     * envelope fields required.
     *
     * <p>Returns {@code null} to force the caller onto the full-tree path for any shape it cannot
     * reproduce exactly. Correctness is never traded for speed.
     *
     * @param line The raw NDJSON line.
     * @return A populated {@link LazyCveDocument}, or {@code null} to signal a full-tree fallback.
     * @throws IOException If the line is not well-formed JSON.
     */
    LazyCveDocument parseLazyCve(String line) throws IOException {
        String resource = null;
        String name = null;
        long offset = 0;
        boolean hasOffset = false;
        String documentRaw = null;

        JsonFactory factory = this.mapper.getFactory();
        try (JsonParser parser = factory.createParser(line)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return null;
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String field = parser.currentName();
                JsonToken value = parser.nextToken();
                if (field == null) {
                    return null;
                }
                switch (field) {
                    case Constants.KEY_RESOURCE:
                        resource = parser.getValueAsString();
                        break;
                    case Constants.KEY_NAME:
                        name = parser.getValueAsString();
                        break;
                    case Constants.KEY_OFFSET:
                        if (value == null || !value.isNumeric()) {
                            return null;
                        }
                        offset = parser.getLongValue();
                        hasOffset = true;
                        break;
                    case Constants.KEY_PAYLOAD:
                        if (value != JsonToken.START_OBJECT) {
                            return null;
                        }
                        documentRaw = this.extractDocumentRaw(parser, line);
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }

        String resourceName = resource != null ? resource : name;
        if (resourceName == null || documentRaw == null) {
            return null;
        }
        String type = Cve.deriveType(resourceName);
        if (type == null) {
            return null;
        }
        return new LazyCveDocument(resourceName, offset, hasOffset, type, documentRaw);
    }

    /**
     * Descends into the {@code payload} object and returns the raw JSON text of the CVE document.
     *
     * <p>Returns {@code null} to force a fallback for any shape it cannot reproduce exactly.
     */
    private String extractDocumentRaw(JsonParser parser, String line) throws IOException {
        long payloadStart = parser.currentTokenLocation().getCharOffset();
        String document = null;
        String legacy = null;
        boolean hasTypeOrOffset = false;

        while (parser.nextToken() != JsonToken.END_OBJECT) {
            String field = parser.currentName();
            JsonToken value = parser.nextToken();
            boolean wrapper = Constants.KEY_DOCUMENT.equals(field) || Constants.KEY_PAYLOAD.equals(field);
            if (wrapper && (value == JsonToken.START_OBJECT || value == JsonToken.START_ARRAY)) {
                String raw = this.sliceCurrentValue(parser, line);
                if (raw == null) {
                    return null;
                }
                if (Constants.KEY_DOCUMENT.equals(field)) {
                    document = raw;
                } else {
                    legacy = raw;
                }
            } else {
                if (Constants.KEY_TYPE.equals(field) || Constants.KEY_OFFSET.equals(field)) {
                    hasTypeOrOffset = true;
                }
                parser.skipChildren();
            }
        }
        long payloadEnd = parser.currentLocation().getCharOffset();

        if (document != null) {
            return document;
        }
        if (legacy != null) {
            return legacy;
        }
        if (!hasTypeOrOffset
                && payloadStart >= 0
                && payloadEnd > payloadStart
                && payloadEnd <= line.length()) {
            return line.substring((int) payloadStart, (int) payloadEnd);
        }
        return null;
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

    /** The envelope fields extracted from a snapshot NDJSON line by {@link #parseEnvelope(String)} */
    static final class Envelope {
        String resourceName;
        long offset;
        boolean hasOffset;
        boolean hasPayload;
        JsonNode payload;
    }

    /**
     * Partial parse of a snapshot NDJSON envelope for the transform path
     *
     * <p>Rather than materializing the whole line into a Jackson tree, it walks the token stream
     * once, reads the small top-level envelope fields, and materializes a {@code JsonNode} for the
     * {@code payload} value only. The outer envelope wrapper is never turned into objects.
     *
     * @param line The raw NDJSON line.
     * @return The extracted {@link Envelope}. {@code hasPayload} is {@code false} when the line is
     *     not a JSON object or carries no {@code payload} field.
     * @throws IOException If the line is not well-formed JSON.
     */
    Envelope parseEnvelope(String line) throws IOException {
        Envelope envelope = new Envelope();
        String resource = null;
        String name = null;

        try (JsonParser parser = this.mapper.getFactory().createParser(line)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return envelope;
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                if (field == null) {
                    return envelope;
                }
                switch (field) {
                    case Constants.KEY_RESOURCE:
                        resource = parser.getValueAsString();
                        break;
                    case Constants.KEY_NAME:
                        name = parser.getValueAsString();
                        break;
                    case Constants.KEY_OFFSET:
                        envelope.offset = parser.getValueAsLong();
                        envelope.hasOffset = true;
                        break;
                    case Constants.KEY_PAYLOAD:
                        envelope.hasPayload = true;
                        envelope.payload = parser.readValueAsTree();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }

        envelope.resourceName = resource != null ? resource : name;
        return envelope;
    }
}
