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
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Serializes the resource-creation-limit check-then-act sequence (count existing documents, then
 * create if under the configured max) with a short-lived mutex document per (resource type, space).
 *
 * <p>The mutex is a document with a deterministic ID, created via {@link
 * DocWriteRequest.OpType#CREATE} so only one caller can hold it at a time for a given resource type
 * and space -- the same atomic-guard technique used by {@link SpaceService#initializeSpace}. The
 * resource count itself remains a live search against the resource index; the lock only prevents
 * two requests from evaluating that count concurrently.
 *
 * <p>{@link Constants#INDEX_RESOURCE_LOCKS} is plugin-internal bookkeeping and is never addressed
 * by API consumers, so every operation on it runs with the caller's security context stashed and is
 * therefore evaluated as the plugin itself. No role needs index-level privileges (in particular
 * {@code indices:admin/create}) on the lock index for its holder to create content resources. The
 * index is provisioned at node startup by {@code ContentManagerPlugin.start()}; {@link
 * #acquire(String, String, ActionListener)} still recreates it on demand in case it is deleted
 * while the node is running.
 *
 * <p>The stash covers the lock index only: the listener passed to {@link #acquire(String, String,
 * ActionListener)} is invoked with the caller's context restored, so the resource creation it goes
 * on to perform is still authorized as the REST user.
 */
public class ResourceLockService {
    private static final Logger log = LogManager.getLogger(ResourceLockService.class);
    private static final String MAPPING_PATH = "/mappings/resource-locks-mapping.json";
    private static final String ACQUIRED_AT_FIELD = "acquired_at";

    private final Client client;
    private final ThreadPool threadPool;

    /**
     * Constructor.
     *
     * @param client OpenSearch client used for index operations.
     * @param threadPool Thread pool used for scheduling retry backoff and for stashing the caller's
     *     security context.
     */
    public ResourceLockService(Client client, ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
    }

    /**
     * Stashes the current thread context (removing the caller's security identity) so that subsequent
     * client operations run as the plugin itself, which owns the lock index.
     *
     * @return a {@link ThreadContext.StoredContext} that must be closed to restore the original
     *     context (use in try-with-resources).
     */
    private ThreadContext.StoredContext stashContext() {
        return this.threadPool.getThreadContext().stashContext();
    }

    /**
     * Creates the lock index if it does not exist yet. Called once per node at plugin startup so the
     * index is provisioned before any REST request needs it, instead of being created on the request
     * path.
     *
     * @return the CreateIndexResponse, or null if the index already exists or its mapping could not
     *     be read.
     * @throws ExecutionException if the client failed to execute the request.
     * @throws InterruptedException if the current thread was interrupted while waiting for the
     *     response.
     * @throws TimeoutException if the operation exceeded the configured client timeout.
     */
    public CreateIndexResponse createIndex()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Stash the caller's security context so the client runs as the plugin, which owns this index.
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            CreateIndexRequest request;
            try {
                request = buildCreateIndexRequest();
            } catch (IOException e) {
                log.error(
                        "Could not read mappings for index [{}]: {}",
                        Constants.INDEX_RESOURCE_LOCKS,
                        e.getMessage());
                return null;
            }

            try {
                return this.client
                        .admin()
                        .indices()
                        .create(request)
                        .get(PluginSettings.getInstance().getClientTimeout(), TimeUnit.SECONDS);
            } catch (ExecutionException | TimeoutException e) {
                boolean alreadyExists =
                        e instanceof ExecutionException
                                ? ExceptionsHelper.unwrap(e, ResourceAlreadyExistsException.class) != null
                                : ClusterInfo.indexExists(this.client, Constants.INDEX_RESOURCE_LOCKS);
                if (alreadyExists) {
                    log.debug(
                            "Index [{}] already exists, skipping creation.", Constants.INDEX_RESOURCE_LOCKS);
                    return null;
                }
                throw e;
            }
        }
    }

    /**
     * Acquires the mutex for the given resource type and space asynchronously, retrying (with bounded
     * retries) until it becomes available.
     *
     * @param resourceType The resource type (e.g. "rule", "filter").
     * @param space The space the resource is being created in.
     * @param listener Notified with the lock document ID on success, or an {@link IOException} if the
     *     lock could not be acquired after {@link Constants#MAX_LOCK_ACQUIRE_RETRIES} attempts.
     */
    public void acquire(String resourceType, String space, ActionListener<String> listener) {
        // Only the lock index is touched as the plugin. The caller's continuation creates the actual
        // content resource, so it must keep running as the REST user for its index-level privileges to
        // be enforced: capture the caller's context before the first stash and restore it around the
        // callback.
        ActionListener<String> callerContextListener =
                ContextPreservingActionListener.wrapPreservingContext(
                        listener, this.threadPool.getThreadContext());
        this.ensureIndexExists(
                ActionListener.wrap(
                        v -> {
                            String lockId = lockId(resourceType, space);
                            this.tryAcquire(lockId, resourceType, space, 1, callerContextListener);
                        },
                        callerContextListener::onFailure));
    }

    private void tryAcquire(
            String lockId,
            String resourceType,
            String space,
            int attempt,
            ActionListener<String> listener) {
        if (attempt > Constants.MAX_LOCK_ACQUIRE_RETRIES) {
            listener.onFailure(
                    new IOException(
                            "Timed out waiting for the resource-creation lock on ["
                                    + resourceType
                                    + "/"
                                    + space
                                    + "]."));
            return;
        }

        IndexRequest request =
                new IndexRequest(Constants.INDEX_RESOURCE_LOCKS)
                        .id(lockId)
                        .source(Map.of(ACQUIRED_AT_FIELD, Instant.now().toEpochMilli()))
                        .opType(DocWriteRequest.OpType.CREATE)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.index(
                    request,
                    ActionListener.wrap(
                            response -> listener.onResponse(lockId),
                            e -> {
                                if (ExceptionsHelper.unwrap(e, VersionConflictEngineException.class) == null) {
                                    listener.onFailure(e);
                                    return;
                                }
                                this.stealIfStale(
                                        lockId,
                                        ActionListener.wrap(
                                                stolen -> {
                                                    if (stolen) {
                                                        this.tryAcquire(lockId, resourceType, space, attempt + 1, listener);
                                                    } else {
                                                        this.threadPool.schedule(
                                                                () ->
                                                                        this.tryAcquire(
                                                                                lockId, resourceType, space, attempt + 1, listener),
                                                                TimeValue.timeValueMillis(
                                                                        Constants.LOCK_ACQUIRE_RETRY_BACKOFF_MILLIS),
                                                                ThreadPool.Names.GENERIC);
                                                    }
                                                },
                                                ex ->
                                                        this.threadPool.schedule(
                                                                () ->
                                                                        this.tryAcquire(
                                                                                lockId, resourceType, space, attempt + 1, listener),
                                                                TimeValue.timeValueMillis(
                                                                        Constants.LOCK_ACQUIRE_RETRY_BACKOFF_MILLIS),
                                                                ThreadPool.Names.GENERIC)));
                            }));
        }
    }

    /**
     * Releases a previously acquired lock. Failures are logged and swallowed so a release problem
     * never surfaces as a resource-creation failure; a lock older than {@link
     * Constants#LOCK_STALE_THRESHOLD_MILLIS} is stolen by the next caller regardless.
     *
     * @param lockId The lock document ID returned by {@link #acquire(String, String,
     *     ActionListener)}.
     */
    public void release(String lockId) {
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.delete(
                    new DeleteRequest(Constants.INDEX_RESOURCE_LOCKS, lockId)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE),
                    ActionListener.wrap(
                            response -> {},
                            e ->
                                    log.warn(
                                            "Failed to release resource-creation lock [{}]: {}",
                                            lockId,
                                            e.getMessage())));
        }
    }

    /**
     * Deletes the lock document if it was acquired more than {@link
     * Constants#LOCK_STALE_THRESHOLD_MILLIS} ago, guarding against a lock orphaned by a crashed node.
     * Never calls {@link ActionListener#onFailure}; all errors resolve to {@code onResponse(false)}.
     *
     * @param lockId The lock document ID.
     * @param listener Notified with {@code true} if the stale lock was stolen (deleted) and the
     *     caller should retry immediately.
     */
    private void stealIfStale(String lockId, ActionListener<Boolean> listener) {
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.get(
                    new GetRequest(Constants.INDEX_RESOURCE_LOCKS, lockId),
                    ActionListener.wrap(
                            response -> {
                                if (!response.isExists()) {
                                    listener.onResponse(true);
                                    return;
                                }
                                Map<String, Object> source = response.getSourceAsMap();
                                Object acquiredAt = source != null ? source.get(ACQUIRED_AT_FIELD) : null;
                                long acquiredAtMillis =
                                        acquiredAt instanceof Number ? ((Number) acquiredAt).longValue() : 0L;
                                if (Instant.now().toEpochMilli() - acquiredAtMillis
                                        <= Constants.LOCK_STALE_THRESHOLD_MILLIS) {
                                    listener.onResponse(false);
                                    return;
                                }
                                log.warn("Stealing stale resource-creation lock [{}].", lockId);
                                this.deleteStaleLock(lockId, listener);
                            },
                            e -> {
                                log.warn(
                                        "Failed to check staleness of resource-creation lock [{}]: {}",
                                        lockId,
                                        e.getMessage());
                                listener.onResponse(false);
                            }));
        }
    }

    private void deleteStaleLock(String lockId, ActionListener<Boolean> listener) {
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.delete(
                    new DeleteRequest(Constants.INDEX_RESOURCE_LOCKS, lockId)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE),
                    ActionListener.wrap(
                            deleteResponse -> listener.onResponse(true),
                            e -> {
                                log.warn(
                                        "Failed to steal stale resource-creation lock" + " [{}]: {}",
                                        lockId,
                                        e.getMessage());
                                listener.onResponse(false);
                            }));
        }
    }

    private static String lockId(String resourceType, String space) {
        return UUID.nameUUIDFromBytes(
                        ("resource-limit-lock-" + resourceType + "-" + space).getBytes(StandardCharsets.UTF_8))
                .toString();
    }

    private void ensureIndexExists(ActionListener<Void> listener) {
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            ClusterInfo.indexExists(
                    this.client,
                    Constants.INDEX_RESOURCE_LOCKS,
                    ActionListener.wrap(
                            exists -> {
                                if (exists) {
                                    listener.onResponse(null);
                                    return;
                                }
                                this.createIndexAsync(listener);
                            },
                            listener::onFailure));
        }
    }

    private void createIndexAsync(ActionListener<Void> listener) {
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            CreateIndexRequest request;
            try {
                request = buildCreateIndexRequest();
            } catch (IOException e) {
                log.error(
                        "Could not read mappings for index [{}]: {}",
                        Constants.INDEX_RESOURCE_LOCKS,
                        e.getMessage());
                listener.onResponse(null);
                return;
            }

            this.client
                    .admin()
                    .indices()
                    .create(
                            request,
                            ActionListener.wrap(
                                    response -> listener.onResponse(null),
                                    e -> {
                                        if (ExceptionsHelper.unwrap(e, ResourceAlreadyExistsException.class) != null) {
                                            log.debug(
                                                    "Index [{}] already exists, skipping creation.",
                                                    Constants.INDEX_RESOURCE_LOCKS);
                                            listener.onResponse(null);
                                        } else {
                                            listener.onFailure(e);
                                        }
                                    }));
        }
    }

    private static CreateIndexRequest buildCreateIndexRequest() throws IOException {
        Settings settings =
                Settings.builder()
                        .put("index.number_of_replicas", 0)
                        .put("index.auto_expand_replicas", "0-1")
                        .put("index.hidden", true)
                        .put(Constants.KEY_INDEX_CODEC, Constants.CODEC_ZSTD)
                        .put(Constants.KEY_INDEX_REFRESH_INTERVAL, Constants.REFRESH_INTERVAL_DISABLED)
                        .build();

        return new CreateIndexRequest()
                .index(Constants.INDEX_RESOURCE_LOCKS)
                .mapping(loadMappingFromResources())
                .settings(settings);
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
