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
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
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
import java.util.concurrent.ConcurrentHashMap;
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
 *
 * <p>The same index also holds named, long-held locks for work that must run on one node at a time
 * across the cluster, such as the catalog sync: see {@link #tryAcquireOnce(String,
 * ActionListener)}, {@link #renew(String)} and {@link #release(String, Runnable)}. Each lock is its
 * own document, so a named lock never blocks a resource-creation lock, nor the other way round.
 */
public class ResourceLockService {
    private static final Logger log = LogManager.getLogger(ResourceLockService.class);
    private static final String MAPPING_PATH = "/mappings/resource-locks-mapping.json";
    private static final String ACQUIRED_AT_FIELD = "acquired_at";

    private final Client client;
    private final ThreadPool threadPool;

    /**
     * The version of each lock this node holds, so renewing and releasing can be conditioned on the
     * document still being the one it took. Refreshed on every renewal, which rewrites the document.
     */
    private final Map<String, long[]> heldVersions = new ConcurrentHashMap<>();

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
     *     lock could not be acquired after {@link PluginSettings#RESOURCE_LOCK_MAX_RETRIES} attempts.
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
        if (attempt > PluginSettings.getInstance().getResourceLockMaxRetries()) {
            listener.onFailure(
                    new ResourceLockTimeoutException(
                            "Timed out waiting for the resource-creation lock on ["
                                    + resourceType
                                    + "/"
                                    + space
                                    + "]."));
            return;
        }

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.index(
                    lockRequest(lockId),
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
                                                                        PluginSettings.getInstance()
                                                                                .getResourceLockRetryBackoffMillis()),
                                                                ThreadPool.Names.GENERIC);
                                                    }
                                                },
                                                ex ->
                                                        this.threadPool.schedule(
                                                                () ->
                                                                        this.tryAcquire(
                                                                                lockId, resourceType, space, attempt + 1, listener),
                                                                TimeValue.timeValueMillis(
                                                                        PluginSettings.getInstance()
                                                                                .getResourceLockRetryBackoffMillis()),
                                                                ThreadPool.Names.GENERIC)));
                            }));
        }
    }

    /**
     * Tries once to take a named lock, without the retry budget of {@link #acquire(String, String,
     * ActionListener)}: a lock held by someone else is reported as not acquired straight away, unless
     * it is stale, in which case it is stolen and taken. Meant for work that can run for longer than
     * {@link PluginSettings#RESOURCE_LOCK_STALE_THRESHOLD_MILLIS}; the holder keeps the lock by
     * calling {@link #renew(String)} more often than that, and a holder that dies stops renewing, so
     * the lock goes stale and the next caller takes it over.
     *
     * @param lockId The lock document ID. The caller owns the name.
     * @param listener Notified with {@code true} if this caller now holds the lock, {@code false} if
     *     another caller holds it, or a failure if the lock index could not be reached.
     */
    public void tryAcquireOnce(String lockId, ActionListener<Boolean> listener) {
        ActionListener<Boolean> callerContextListener =
                ContextPreservingActionListener.wrapPreservingContext(
                        listener, this.threadPool.getThreadContext());
        this.ensureIndexExists(
                ActionListener.wrap(
                        v -> this.createLockDocument(lockId, true, callerContextListener),
                        callerContextListener::onFailure));
    }

    private void createLockDocument(
            String lockId, boolean stealIfStale, ActionListener<Boolean> listener) {
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.index(
                    lockRequest(lockId),
                    ActionListener.wrap(
                            response -> {
                                this.heldVersions.put(
                                        lockId, new long[] {response.getSeqNo(), response.getPrimaryTerm()});
                                listener.onResponse(true);
                            },
                            e -> {
                                if (ExceptionsHelper.unwrap(e, VersionConflictEngineException.class) == null) {
                                    listener.onFailure(e);
                                    return;
                                }
                                if (!stealIfStale) {
                                    listener.onResponse(false);
                                    return;
                                }
                                // stealIfStale never fails, it resolves every error to false.
                                this.stealIfStale(
                                        lockId,
                                        ActionListener.wrap(
                                                stolen -> {
                                                    if (stolen) {
                                                        this.createLockDocument(lockId, false, listener);
                                                    } else {
                                                        listener.onResponse(false);
                                                    }
                                                },
                                                listener::onFailure));
                            }));
        }
    }

    /**
     * Refreshes the acquisition time of a lock taken with {@link #tryAcquireOnce(String,
     * ActionListener)}, so it is not considered stale while its holder is still working. Only updates
     * an existing document, never creates one. Failures are logged and swallowed.
     *
     * @param lockId The lock document ID.
     */
    public void renew(String lockId) {
        this.renew(lockId, () -> {});
    }

    /**
     * Refreshes a lock, only while it is still the version this node took. Unconditional, the renewal
     * keeps alive a lock another node has taken over, and its holder never finds out it lost it.
     *
     * @param lockId The lock document ID.
     * @param onLockLost Run when the lock is no longer this node's. No later renewal can succeed, so
     *     the caller is expected to stop renewing.
     */
    public void renew(String lockId, Runnable onLockLost) {
        UpdateRequest request =
                new UpdateRequest(Constants.INDEX_RESOURCE_LOCKS, lockId)
                        .doc(Map.of(ACQUIRED_AT_FIELD, Instant.now().toEpochMilli()));
        long[] version = this.heldVersions.get(lockId);
        // A lock this node did not take leaves the update unconditional, as it was before.
        if (version != null) {
            request.setIfSeqNo(version[0]).setIfPrimaryTerm(version[1]);
        }
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.update(
                    request,
                    ActionListener.wrap(
                            response ->
                                    this.heldVersions.put(
                                            lockId, new long[] {response.getSeqNo(), response.getPrimaryTerm()}),
                            e -> {
                                if (ExceptionsHelper.unwrap(e, VersionConflictEngineException.class) != null) {
                                    log.warn("Lock [{}] was taken over while this pass was running.", lockId);
                                    this.heldVersions.remove(lockId);
                                    onLockLost.run();
                                    return;
                                }
                                // The exception, not its message: on a RemoteTransportException the
                                // message is only [node][address][action].
                                log.warn("Failed to renew lock [{}]", lockId, e);
                            }));
        }
    }

    /**
     * Releases a previously acquired lock. Failures are logged and swallowed so a release problem
     * never surfaces as a resource-creation failure; a lock older than {@link
     * PluginSettings#RESOURCE_LOCK_STALE_THRESHOLD_MILLIS} is stolen by the next caller regardless.
     *
     * @param lockId The lock document ID returned by {@link #acquire(String, String,
     *     ActionListener)}.
     */
    public void release(String lockId) {
        this.release(lockId, () -> {});
    }

    /**
     * Releases a previously acquired lock and runs {@code onReleased} once the delete has completed,
     * whatever its outcome. Lets a caller that takes the same lock again right away wait for the
     * document to be gone, instead of finding it still there. Failures are logged and swallowed.
     *
     * <p>Only deletes the version this node took. Unconditional, a holder that lost the lock deletes
     * the new holder's and leaves it free while a pass is still running.
     *
     * @param lockId The lock document ID.
     * @param onReleased Run exactly once, after the delete succeeded or failed.
     */
    public void release(String lockId, Runnable onReleased) {
        DeleteRequest request =
                new DeleteRequest(Constants.INDEX_RESOURCE_LOCKS, lockId)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        long[] version = this.heldVersions.remove(lockId);
        // A lock this node did not take leaves the delete unconditional, as it was before.
        if (version != null) {
            request.setIfSeqNo(version[0]).setIfPrimaryTerm(version[1]);
        }
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.delete(
                    request,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(DeleteResponse response) {
                            onReleased.run();
                        }

                        @Override
                        public void onFailure(Exception e) {
                            if (ExceptionsHelper.unwrap(e, VersionConflictEngineException.class) != null) {
                                log.debug("Lock [{}] was taken over before this node released it.", lockId);
                            } else {
                                log.warn("Failed to release lock [{}]: {}", lockId, e.getMessage());
                            }
                            onReleased.run();
                        }
                    });
        }
    }

    private static IndexRequest lockRequest(String lockId) {
        return new IndexRequest(Constants.INDEX_RESOURCE_LOCKS)
                .id(lockId)
                .source(Map.of(ACQUIRED_AT_FIELD, Instant.now().toEpochMilli()))
                .opType(DocWriteRequest.OpType.CREATE)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
    }

    /**
     * Deletes the lock document if it was acquired more than {@link
     * PluginSettings#RESOURCE_LOCK_STALE_THRESHOLD_MILLIS} ago, guarding against a lock orphaned by a
     * crashed node. Never calls {@link ActionListener#onFailure}; all errors resolve to {@code
     * onResponse(false)}.
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
                                        <= PluginSettings.getInstance().getResourceLockStaleThresholdMillis()) {
                                    listener.onResponse(false);
                                    return;
                                }
                                log.warn("Stealing stale resource-creation lock [{}].", lockId);
                                this.deleteStaleLock(
                                        lockId, response.getSeqNo(), response.getPrimaryTerm(), listener);
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

    /**
     * Deletes a lock found stale, only while it is still the version that was read as stale. Two
     * callers that see the same stale lock would otherwise both delete it: the second delete would
     * remove the fresh lock the first had just created in its place, and both would hold the lock.
     */
    private void deleteStaleLock(
            String lockId, long seqNo, long primaryTerm, ActionListener<Boolean> listener) {
        DeleteRequest request =
                new DeleteRequest(Constants.INDEX_RESOURCE_LOCKS, lockId)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        // A version the GET did not report leaves the delete unconditional, as it was before.
        if (seqNo >= 0 && primaryTerm > 0) {
            request.setIfSeqNo(seqNo).setIfPrimaryTerm(primaryTerm);
        }
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.delete(
                    request,
                    ActionListener.wrap(
                            deleteResponse -> listener.onResponse(true),
                            e -> {
                                if (ExceptionsHelper.unwrap(e, VersionConflictEngineException.class) != null) {
                                    log.debug("Stale lock [{}] was taken over by another caller first.", lockId);
                                } else {
                                    log.warn(
                                            "Failed to steal stale resource-creation lock" + " [{}]: {}",
                                            lockId,
                                            e.getMessage());
                                }
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
