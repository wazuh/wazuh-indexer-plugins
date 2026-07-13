/*
 * Copyright (C) 2026, Wazuh Inc.
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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import com.wazuh.contentmanager.utils.ClusterInfo;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Serializes the resource-creation-limit check-then-act sequence (count existing documents, then
 * create if under the configured max) with a short-lived mutex document per (resource type, space).
 *
 * <p>The mutex is a document with a deterministic ID, created via {@link
 * DocWriteRequest.OpType#CREATE} so only one caller can hold it at a time for a given resource type
 * and space -- the same atomic-guard technique used by {@link SpaceService#initializeSpace(String,
 * String)}. The resource count itself remains a live search against the resource index; the lock
 * only prevents two requests from evaluating that count concurrently.
 */
public class ResourceLockService {
    private static final Logger log = LogManager.getLogger(ResourceLockService.class);
    private static final String MAPPING_PATH = "/mappings/resource-locks-mapping.json";
    private static final String ACQUIRED_AT_FIELD = "acquired_at";

    private final Client client;

    /**
     * Constructor.
     *
     * @param client OpenSearch client used for index operations.
     */
    public ResourceLockService(Client client) {
        this.client = client;
    }

    /**
     * Acquires the mutex for the given resource type and space, blocking (with bounded retries) until
     * it becomes available.
     *
     * @param resourceType The resource type (e.g. "rule", "filter").
     * @param space The space the resource is being created in.
     * @return The lock document ID, to be passed to {@link #release(String)}.
     * @throws IOException If the lock could not be acquired after {@link
     *     Constants#MAX_LOCK_ACQUIRE_RETRIES} attempts.
     */
    public String acquire(String resourceType, String space) throws IOException {
        this.ensureIndexExists();
        String lockId = lockId(resourceType, space);

        for (int attempt = 1; attempt <= Constants.MAX_LOCK_ACQUIRE_RETRIES; attempt++) {
            try {
                IndexRequest request =
                        new IndexRequest(Constants.INDEX_RESOURCE_LOCKS)
                                .id(lockId)
                                .source(Map.of(ACQUIRED_AT_FIELD, Instant.now().toEpochMilli()))
                                .opType(DocWriteRequest.OpType.CREATE)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                this.client.index(request).actionGet();
                return lockId;
            } catch (VersionConflictEngineException e) {
                if (this.stealIfStale(lockId)) {
                    continue;
                }
                this.backoff();
            }
        }
        throw new IOException(
                "Timed out waiting for the resource-creation lock on ["
                        + resourceType
                        + "/"
                        + space
                        + "].");
    }

    /**
     * Releases a previously acquired lock. Failures are logged and swallowed so a release problem
     * never surfaces as a resource-creation failure; a lock older than {@link
     * Constants#LOCK_STALE_THRESHOLD_MILLIS} is stolen by the next caller regardless.
     *
     * @param lockId The lock document ID returned by {@link #acquire(String, String)}.
     */
    public void release(String lockId) {
        try {
            this.client
                    .delete(
                            new DeleteRequest(Constants.INDEX_RESOURCE_LOCKS, lockId)
                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                    .actionGet();
        } catch (Exception e) {
            log.warn("Failed to release resource-creation lock [{}]: {}", lockId, e.getMessage());
        }
    }

    /**
     * Deletes the lock document if it was acquired more than {@link
     * Constants#LOCK_STALE_THRESHOLD_MILLIS} ago, guarding against a lock orphaned by a crashed node.
     *
     * @param lockId The lock document ID.
     * @return true if the stale lock was stolen (deleted) and the caller should retry immediately.
     */
    private boolean stealIfStale(String lockId) {
        try {
            GetResponse response =
                    this.client.get(new GetRequest(Constants.INDEX_RESOURCE_LOCKS, lockId)).actionGet();
            if (!response.isExists()) {
                // Released concurrently between our failed acquire and this check; retry immediately.
                return true;
            }
            Map<String, Object> source = response.getSourceAsMap();
            Object acquiredAt = source != null ? source.get(ACQUIRED_AT_FIELD) : null;
            long acquiredAtMillis = acquiredAt instanceof Number ? ((Number) acquiredAt).longValue() : 0L;
            if (Instant.now().toEpochMilli() - acquiredAtMillis
                    <= Constants.LOCK_STALE_THRESHOLD_MILLIS) {
                return false;
            }
            log.warn("Stealing stale resource-creation lock [{}].", lockId);
            this.client
                    .delete(
                            new DeleteRequest(Constants.INDEX_RESOURCE_LOCKS, lockId)
                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                    .actionGet();
            return true;
        } catch (Exception e) {
            log.warn(
                    "Failed to check staleness of resource-creation lock [{}]: {}", lockId, e.getMessage());
            return false;
        }
    }

    private void backoff() {
        try {
            Thread.sleep(Constants.LOCK_ACQUIRE_RETRY_BACKOFF_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String lockId(String resourceType, String space) {
        return UUID.nameUUIDFromBytes(
                        ("resource-limit-lock-" + resourceType + "-" + space).getBytes(StandardCharsets.UTF_8))
                .toString();
    }

    private void ensureIndexExists() {
        if (ClusterInfo.indexExists(this.client, Constants.INDEX_RESOURCE_LOCKS)) {
            return;
        }
        Settings settings =
                Settings.builder()
                        .put("index.number_of_replicas", 0)
                        .put("index.hidden", true)
                        .put(Constants.KEY_INDEX_CODEC, Constants.CODEC_ZSTD)
                        .put(Constants.KEY_INDEX_REFRESH_INTERVAL, Constants.REFRESH_INTERVAL_DISABLED)
                        .build();

        String mappings;
        try {
            mappings = loadMappingFromResources();
        } catch (IOException e) {
            log.error(
                    "Could not read mappings for index [{}]: {}",
                    Constants.INDEX_RESOURCE_LOCKS,
                    e.getMessage());
            return;
        }

        CreateIndexRequest request =
                new CreateIndexRequest()
                        .index(Constants.INDEX_RESOURCE_LOCKS)
                        .mapping(mappings)
                        .settings(settings);
        try {
            this.client.admin().indices().create(request).actionGet();
        } catch (Exception e) {
            if (ExceptionsHelper.unwrap(e, ResourceAlreadyExistsException.class) != null) {
                log.debug("Index [{}] already exists, skipping creation.", Constants.INDEX_RESOURCE_LOCKS);
                return;
            }
            throw e;
        }
    }

    private static String loadMappingFromResources() throws IOException {
        try (InputStream is = ResourceLockService.class.getResourceAsStream(MAPPING_PATH)) {
            if (is == null) {
                throw new java.io.FileNotFoundException("Mapping file not found: " + MAPPING_PATH);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
