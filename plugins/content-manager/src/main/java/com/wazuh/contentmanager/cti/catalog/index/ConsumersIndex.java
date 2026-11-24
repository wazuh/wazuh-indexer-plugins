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
package com.wazuh.contentmanager.cti.catalog.index;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.UnaryOperator;

import com.wazuh.contentmanager.cti.catalog.model.EngineLoadFailure;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;
import com.wazuh.contentmanager.utils.Constants;

/** Class to manage the Context index. */
public class ConsumersIndex {
    private static final Logger log = LogManager.getLogger(ConsumersIndex.class);

    /** The name of the Contexts index */
    public static final String INDEX_NAME = ".wazuh-cti-consumers";

    /**
     * Id of the document that holds the state of the CTI catalog as a whole, next to the documents of
     * each consumer type.
     */
    public static final String CATALOG_ID = "cti:catalog:global";

    /** Path of the index mapping file */
    private static final String MAPPING_PATH = "/mappings/consumers-mapping.json";

    /**
     * Attempts at a conditional write of a consumer document when another writer keeps changing the
     * stored document between the read and the write.
     */
    static final int MAX_WRITE_ATTEMPTS = 5;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Outcome of {@link #updateEngineLoadFailures}. */
    public enum EngineLoadUpdate {
        /** The consumer document does not exist, so there was nothing to record into. */
        ABSENT,
        /** The document already held the failures to record: nothing was written. */
        UNCHANGED,
        /** The document was written with the new failures. */
        WRITTEN
    }

    /** A consumer document as stored, with the sequence number and primary term it was read at. */
    private record StoredConsumer(LocalConsumer consumer, long seqNo, long primaryTerm) {}

    private final Client client;
    private final PluginSettings pluginSettings;

    /**
     * Constructor.
     *
     * @param client OpenSearch client used for indexing and search operations.
     */
    public ConsumersIndex(Client client) {
        this.client = client;
        this.pluginSettings = PluginSettings.getInstance();
    }

    /**
     * Indexes a local consumer object into the cluster.
     *
     * @param consumer The {@link LocalConsumer} object containing the data to be indexed.
     * @return The {@link IndexResponse} indicating the result of the operation.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting for the
     *     response.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws IOException If there is an error serializing the consumer to XContent.
     * @throws RuntimeException If the target index is not currently ready or available.
     */
    public IndexResponse setConsumer(LocalConsumer consumer)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        return this.setConsumer(consumer, false);
    }

    /**
     * Persists a consumer document to the index.
     *
     * @param consumer The consumer to persist.
     * @param lightweight When true, skips the cluster health check and uses {@link
     *     WriteRequest.RefreshPolicy#NONE} for faster batch checkpoint writes.
     * @return The index response.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws IOException If there is an error serializing the consumer to XContent.
     * @throws RuntimeException If the target index is not currently ready or available.
     */
    public IndexResponse setConsumer(LocalConsumer consumer, boolean lightweight)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        if (!lightweight
                && !ClusterInfo.indexStatusCheck(
                        this.client, INDEX_NAME, this.pluginSettings.getClientTimeout())) {
            throw new RuntimeException("Index not ready");
        }
        String id = consumer.getType();
        WriteRequest.RefreshPolicy refreshPolicy =
                lightweight ? WriteRequest.RefreshPolicy.NONE : WriteRequest.RefreshPolicy.IMMEDIATE;
        if (!ConsumersIndex.holdsEngineLoadState(id)) {
            IndexRequest request =
                    new IndexRequest()
                            .index(INDEX_NAME)
                            .id(id)
                            .source(consumer.toXContent())
                            .setRefreshPolicy(refreshPolicy);
            return this.client
                    .index(request)
                    .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        }
        for (int attempt = 1; ; attempt++) {
            IndexRequest request =
                    this.keepingEngineLoadState(consumer, this.readStored(id))
                            .setRefreshPolicy(refreshPolicy);
            try {
                return this.client
                        .index(request)
                        .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
            } catch (ExecutionException e) {
                if (attempt >= MAX_WRITE_ATTEMPTS || !ConsumersIndex.isVersionConflict(e)) {
                    throw e;
                }
                log.debug(Constants.D_LOG_CONSUMER_WRITE_CONFLICT, id, attempt);
            }
        }
    }

    /**
     * Persists several consumer documents in one request. A single refresh makes them visible
     * together, so a reader never sees some of them changed and the others not.
     *
     * <p>The ruleset consumer document keeps the Engine load state it has stored, as in {@link
     * #setConsumer(LocalConsumer, boolean)}. If another writer changed that document between its read
     * and the bulk request, it is written again on its own, on top of that change.
     *
     * @param consumers The consumers to persist.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws IOException If there is an error serializing a consumer to XContent.
     * @throws IllegalStateException If any of the documents could not be written.
     * @throws RuntimeException If the target index is not currently ready or available.
     */
    public void setConsumers(Collection<LocalConsumer> consumers)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        if (!ClusterInfo.indexStatusCheck(
                this.client, INDEX_NAME, this.pluginSettings.getClientTimeout())) {
            throw new RuntimeException("Index not ready");
        }
        BulkRequest request = new BulkRequest().setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        Map<String, LocalConsumer> byId = new HashMap<>();
        for (LocalConsumer consumer : consumers) {
            String id = consumer.getType();
            byId.put(id, consumer);
            if (ConsumersIndex.holdsEngineLoadState(id)) {
                request.add(this.keepingEngineLoadState(consumer, this.readStored(id)));
            } else {
                request.add(new IndexRequest().index(INDEX_NAME).id(id).source(consumer.toXContent()));
            }
        }
        BulkResponse response =
                this.client.bulk(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        if (!response.hasFailures()) {
            return;
        }
        List<LocalConsumer> conflicted = new ArrayList<>();
        for (BulkItemResponse item : response.getItems()) {
            if (!item.isFailed()) {
                continue;
            }
            if (item.getFailure().getStatus() != RestStatus.CONFLICT
                    || !ConsumersIndex.holdsEngineLoadState(item.getId())) {
                throw new IllegalStateException(response.buildFailureMessage());
            }
            conflicted.add(byId.get(item.getId()));
        }
        for (LocalConsumer consumer : conflicted) {
            log.debug(Constants.D_LOG_CONSUMER_WRITE_CONFLICT, consumer.getType(), 1);
            this.setConsumer(consumer);
        }
    }

    /**
     * Changes the Engine load failures recorded in a consumer document, and nothing else. The stored
     * document is read and written back with its sequence number, so a concurrent write of the
     * document, by the synchronization or by another node, is never lost: a conflict reads it again
     * and reapplies {@code change}, up to {@link #MAX_WRITE_ATTEMPTS} times.
     *
     * @param type The consumer type identifier used as the document id.
     * @param change Computes the failures to record from the ones stored. Called once per attempt, so
     *     it must not have side effects.
     * @return Whether the document was absent, already held the result of {@code change}, or was
     *     written.
     * @throws ExecutionException If the client failed to execute a request, including when every
     *     attempt conflicted.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If a request exceeded the configured client timeout.
     * @throws IOException If the stored document cannot be parsed or the new one built.
     */
    public EngineLoadUpdate updateEngineLoadFailures(
            String type, UnaryOperator<Map<String, EngineLoadFailure>> change)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        for (int attempt = 1; ; attempt++) {
            StoredConsumer stored = this.readStored(type);
            if (stored == null) {
                return EngineLoadUpdate.ABSENT;
            }
            Map<String, EngineLoadFailure> current = stored.consumer().getEngineLoadFailures();
            Map<String, EngineLoadFailure> updated = change.apply(current);
            if (current.equals(updated)) {
                return EngineLoadUpdate.UNCHANGED;
            }
            IndexRequest request =
                    new IndexRequest()
                            .index(INDEX_NAME)
                            .id(type)
                            .source(stored.consumer().withEngineLoadFailures(updated).toXContent())
                            .setIfSeqNo(stored.seqNo())
                            .setIfPrimaryTerm(stored.primaryTerm())
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            try {
                this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
                return EngineLoadUpdate.WRITTEN;
            } catch (ExecutionException e) {
                if (attempt >= MAX_WRITE_ATTEMPTS || !ConsumersIndex.isVersionConflict(e)) {
                    throw e;
                }
                log.debug(Constants.D_LOG_CONSUMER_WRITE_CONFLICT, type, attempt);
            }
        }
    }

    /**
     * Returns whether documents of this consumer type carry Engine load state. Only the ruleset is
     * loaded into the Engine by {@code EngineContentLoader}; the other consumers keep the plain
     * write, with no read before it.
     *
     * @param type The consumer type identifier.
     * @return {@code true} for the ruleset consumer.
     */
    private static boolean holdsEngineLoadState(String type) {
        return Constants.CONSUMER_TYPE_RULESET.equals(type);
    }

    /**
     * Builds the write of {@code consumer} that keeps the Engine load failures of the stored
     * document. Only the Engine content loader changes them, through {@link
     * #updateEngineLoadFailures}, so any copy the writer holds may be stale and is replaced. The
     * write is conditional on the stored document not having changed since it was read; a new
     * document is created only if there still is none.
     *
     * @param consumer The consumer to write.
     * @param stored The stored document, or {@code null} if there is none.
     * @return The index request, without a refresh policy.
     * @throws IOException If the document cannot be built.
     */
    private IndexRequest keepingEngineLoadState(LocalConsumer consumer, StoredConsumer stored)
            throws IOException {
        IndexRequest request = new IndexRequest().index(INDEX_NAME).id(consumer.getType());
        if (stored == null) {
            return request.source(consumer.withEngineLoadFailures(null).toXContent()).create(true);
        }
        return request
                .source(
                        consumer.withEngineLoadFailures(stored.consumer().getEngineLoadFailures()).toXContent())
                .setIfSeqNo(stored.seqNo())
                .setIfPrimaryTerm(stored.primaryTerm());
    }

    /**
     * Reads a consumer document with the sequence number and primary term needed to write it back
     * conditionally. The read prefers the primary copy, whose sequence number is the one a
     * conditional write is checked against.
     *
     * @param type The consumer type identifier used as the document id.
     * @return The stored document, or {@code null} if it, or the index, does not exist.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the request exceeded the configured client timeout.
     * @throws IOException If the document cannot be parsed.
     */
    private StoredConsumer readStored(String type)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        GetResponse response;
        try {
            response =
                    this.client
                            .get(
                                    new GetRequest()
                                            .index(INDEX_NAME)
                                            .id(type)
                                            .preference(Preference.PRIMARY_FIRST.type()))
                            .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            if (ExceptionsHelper.unwrap(e, IndexNotFoundException.class) != null) {
                return null;
            }
            throw e;
        }
        if (response == null || !response.isExists()) {
            return null;
        }
        return new StoredConsumer(
                MAPPER.readValue(response.getSourceAsString(), LocalConsumer.class),
                response.getSeqNo(),
                response.getPrimaryTerm());
    }

    /**
     * Returns whether a failed write was refused because the stored document changed since it was
     * read.
     *
     * @param e The failure.
     * @return {@code true} for a version conflict.
     */
    private static boolean isVersionConflict(Exception e) {
        return ExceptionsHelper.unwrap(e, VersionConflictEngineException.class) != null;
    }

    /**
     * Records the time the Wazuh Indexer last got an answer from the CTI catalog when it asked for
     * updates, in the {@link #CATALOG_ID} document.
     *
     * @param checkedAt The time of the answer.
     * @return The {@link IndexResponse} indicating the result of the operation.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws IOException If the document cannot be built.
     * @throws RuntimeException If the target index is not currently ready or available.
     */
    public IndexResponse setLastCheckedAt(Instant checkedAt)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        if (!ClusterInfo.indexStatusCheck(
                this.client, INDEX_NAME, this.pluginSettings.getClientTimeout())) {
            throw new RuntimeException("Index not ready");
        }
        IndexRequest request =
                new IndexRequest()
                        .index(INDEX_NAME)
                        .id(CATALOG_ID)
                        .source(
                                XContentFactory.jsonBuilder()
                                        .startObject()
                                        .field(Constants.KEY_LAST_CHECKED_AT, checkedAt.toString())
                                        .endObject())
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        return this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Retrieves a consumer document from the index by its composite identifier.
     *
     * @param type The consumer type identifier used as the document id.
     * @return A {@link GetResponse} containing the document source and metadata.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting for the
     *     response.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws RuntimeException If the target index is not currently ready or available.
     */
    public GetResponse getConsumer(String type)
            throws ExecutionException, InterruptedException, TimeoutException {
        // Avoid faulty requests if the cluster is unstable.
        if (!ClusterInfo.indexStatusCheck(
                this.client, INDEX_NAME, this.pluginSettings.getClientTimeout())) {
            throw new RuntimeException("Index not ready");
        }
        GetRequest request = new GetRequest().index(INDEX_NAME).id(type).preference("_local");

        ActionFuture<GetResponse> future = this.client.get(request);

        return future.get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Checks whether the {@link ConsumersIndex#INDEX_NAME} index exists.
     *
     * @see ClusterInfo#indexExists(Client, String)
     * @return true if the index exists, false otherwise.
     */
    public boolean exists() {
        return ClusterInfo.indexExists(this.client, ConsumersIndex.INDEX_NAME);
    }

    /**
     * Creates the {@link ConsumersIndex#INDEX_NAME} index.
     *
     * @return the response of the create index operation, or null if the index already exists.
     * @throws ExecutionException if the client failed to execute the request.
     * @throws InterruptedException if the current thread was interrupted while waiting for the
     *     response.
     * @throws TimeoutException if the operation exceeded the configured client timeout.
     */
    public CreateIndexResponse createIndex()
            throws ExecutionException, InterruptedException, TimeoutException {
        Settings settings =
                Settings.builder()
                        .put("index.number_of_replicas", 0)
                        .put("index.auto_expand_replicas", "0-1")
                        .put("hidden", true)
                        .put(Constants.KEY_INDEX_CODEC, Constants.CODEC_ZSTD)
                        .put(Constants.KEY_INDEX_REFRESH_INTERVAL, Constants.REFRESH_INTERVAL_DISABLED)
                        .build();

        String mappings;
        try {
            mappings = this.loadMappingFromResources();
        } catch (IOException e) {
            log.error("Could not read mappings for index [{}]", INDEX_NAME);
            return null;
        }

        CreateIndexRequest request =
                new CreateIndexRequest().index(INDEX_NAME).mapping(mappings).settings(settings);

        try {
            return this.client
                    .admin()
                    .indices()
                    .create(request)
                    .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        } catch (ExecutionException | TimeoutException e) {
            boolean alreadyExists =
                    e instanceof ExecutionException
                            ? ExceptionsHelper.unwrap(e, ResourceAlreadyExistsException.class) != null
                            : this.exists();
            if (alreadyExists) {
                log.debug("Index [{}] already exists, skipping creation.", INDEX_NAME);
                return null;
            }
            throw e;
        }
    }

    /**
     * Loads the index mapping from the 'resources' folder.
     *
     * @return the mapping as a JSON string.
     * @throws IOException if reading the resource fails.
     */
    protected String loadMappingFromResources() throws IOException {
        try (InputStream is = this.getClass().getResourceAsStream(MAPPING_PATH)) {
            if (is == null) {
                throw new java.io.FileNotFoundException("Mapping file not found: " + MAPPING_PATH);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
