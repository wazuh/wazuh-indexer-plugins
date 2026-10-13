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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.io.CloseMode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.env.Environment;
import org.opensearch.threadpool.ThreadPool;

import java.io.Closeable;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.action.VersionCheckResponse;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.model.Release;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Answers GET /version/check by querying the CTI releases API.
 *
 * <p>The CTI call blocks for up to one client timeout, so it never runs on the calling thread: it
 * is dispatched to its own single-thread pool ({@link PluginSettings#VERSION_CHECK_THREAD_POOL}).
 * At most one call is in flight per node; concurrent checks wait on it and share its answer instead
 * of issuing their own. Calls are rate limited per node by a token bucket: up to {@link
 * #BUCKET_CAPACITY} calls in a burst, refilled at one call per {@link #TOKEN_REFILL_MILLIS}. Each
 * CTI call spends a token whatever its outcome; a check that finds the bucket empty is answered 429
 * with the time until the next token. Nothing is cached, so every answer comes from CTI.
 */
public class VersionCheckService implements Closeable {

    private static final Logger log = LogManager.getLogger(VersionCheckService.class);

    /** Calls allowed in a burst: absorbs double clicks and several users checking at once. */
    static final long BUCKET_CAPACITY = 5;

    /** Time to earn back one call: caps the sustained rate at 5 calls per minute per node. */
    static final long TOKEN_REFILL_MILLIS = TimeUnit.SECONDS.toMillis(12);

    private final Environment environment;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final Supplier<ApiClient> clientFactory;
    private final ObjectMapper mapper = new ObjectMapper();

    private ApiClient client;
    private boolean closed;
    // Token buckete: one token is TOKEN_REFILL_MILLIS of credit
    private long creditMillis = BUCKET_CAPACITY * TOKEN_REFILL_MILLIS;
    private Long lastRefillMillis;
    private List<ActionListener<VersionCheckResponse>> waiting;

    /**
     * Constructs the service.
     *
     * @param environment the node environment, used to resolve the current Wazuh version.
     * @param clusterService the cluster service, used to read the cluster UUID.
     * @param threadPool the thread pool the CTI call is dispatched to.
     */
    public VersionCheckService(
            Environment environment, ClusterService clusterService, ThreadPool threadPool) {
        this(environment, clusterService, threadPool, ApiClient::new);
    }

    VersionCheckService(
            Environment environment,
            ClusterService clusterService,
            ThreadPool threadPool,
            Supplier<ApiClient> clientFactory) {
        this.environment = environment;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.clientFactory = clientFactory;
    }

    /**
     * Resolves the available updates and notifies the listener. Never blocks the calling thread
     *
     * @param listener receives the version-check response; errors, including the rate limit (429),
     *     are reported as a response with an error status, never through {@code onFailure}
     */
    public void check(ActionListener<VersionCheckResponse> listener) {
        ActionListener<VersionCheckResponse> waiter =
                ContextPreservingActionListener.wrapPreservingContext(
                        listener, this.threadPool.getThreadContext());
        long retryAfterMillis;
        synchronized (this) {
            if (this.waiting != null) {
                this.waiting.add(waiter);
                return;
            }
            retryAfterMillis = this.takeToken(this.threadPool.relativeTimeInMillis());
            if (retryAfterMillis == 0) {
                this.waiting = new ArrayList<>();
                this.waiting.add(waiter);
            }
        }
        if (retryAfterMillis > 0) {
            long retryAfterSeconds = TimeUnit.MILLISECONDS.toSeconds(retryAfterMillis + 999);
            listener.onResponse(
                    new VersionCheckResponse(
                            String.format(
                                    Locale.ROOT, Constants.E_429_VERSION_CHECK_RATE_LIMITED, retryAfterSeconds),
                            RestStatus.TOO_MANY_REQUESTS,
                            retryAfterSeconds));
            return;
        }

        try {
            this.threadPool
                    .executor(PluginSettings.VERSION_CHECK_THREAD_POOL)
                    .execute(this::fetchAndComplete);
        } catch (OpenSearchRejectedExecutionException e) {
            log.warn("Version check rejected by its thread pool: {}", e.getMessage());
            synchronized (this) {
                this.creditMillis =
                        Math.min(
                                BUCKET_CAPACITY * TOKEN_REFILL_MILLIS, this.creditMillis + TOKEN_REFILL_MILLIS);
            }
            this.complete(
                    new VersionCheckResponse(
                            Constants.E_429_VERSION_CHECK_BUSY, RestStatus.TOO_MANY_REQUESTS));
        }
    }

    /**
     * Refills the bucket for the time elapsed since the last check and takes one token if available.
     * Caller must hold the lock.
     *
     * @param now the current relative time, in milliseconds.
     * @return {@code 0} if a token was taken, otherwise the milliseconds until the next token.
     */
    private long takeToken(long now) {
        if (this.lastRefillMillis != null) {
            this.creditMillis =
                    Math.min(
                            BUCKET_CAPACITY * TOKEN_REFILL_MILLIS,
                            this.creditMillis + (now - this.lastRefillMillis));
        }
        this.lastRefillMillis = now;
        if (this.creditMillis >= TOKEN_REFILL_MILLIS) {
            this.creditMillis -= TOKEN_REFILL_MILLIS;
            return 0;
        }
        return TOKEN_REFILL_MILLIS - this.creditMillis;
    }

    /**
     * Runs the CTI call and hands the result to every waiting listener. The waiters are released even
     * if {@link #fetch()} throws an {@link Error}; otherwise the in-flight marker would stay set and
     * every later check would queue forever.
     */
    private void fetchAndComplete() {
        VersionCheckResponse response = null;
        try {
            response = this.fetch();
        } finally {
            this.complete(
                    response != null
                            ? response
                            : new VersionCheckResponse(
                                    Constants.E_500_CTI_UNREACHABLE, RestStatus.INTERNAL_SERVER_ERROR));
        }
    }

    /**
     * Publishes a result to the waiting listeners and clears the in-flight marker.
     *
     * @param response the result to publish.
     */
    private void complete(VersionCheckResponse response) {
        List<ActionListener<VersionCheckResponse>> listeners;
        synchronized (this) {
            listeners = this.waiting;
            this.waiting = null;
        }
        for (ActionListener<VersionCheckResponse> listener : listeners) {
            try {
                listener.onResponse(response);
            } catch (Exception e) {
                log.warn("Version check listener failed: {}", e.getMessage(), e);
            }
        }
    }

    /**
     * Queries CTI for the release updates of the running version. Blocking: one CTI round-trip.
     *
     * @return the version-check response, or an error response; never throws.
     */
    VersionCheckResponse fetch() {
        try {
            String version = ContentManagerPlugin.getVersion(this.environment);
            if (version == null || version.isBlank()) {
                log.error(Constants.E_500_VERSION_NOT_FOUND);
                return new VersionCheckResponse(
                        Constants.E_500_VERSION_NOT_FOUND, RestStatus.INTERNAL_SERVER_ERROR);
            }

            String tag = "v" + version;
            SimpleHttpResponse ctiResponse = this.client().getReleaseUpdates(tag);

            int ctiStatusCode = ctiResponse.getCode();
            if (ctiStatusCode < 200 || ctiStatusCode >= 300) {
                log.error(
                        "CTI API returned error for version check: status={}, body={}",
                        ctiStatusCode,
                        ctiResponse.getBodyText());
                RestStatus status =
                        RestStatus.fromCode(ctiStatusCode) != null
                                ? RestStatus.fromCode(ctiStatusCode)
                                : RestStatus.BAD_GATEWAY;
                return new VersionCheckResponse(ctiResponse.getBodyText(), status).parseMessageAsJson();
            }

            JsonNode root = this.mapper.readTree(ctiResponse.getBodyText());
            JsonNode data = root.get("data");

            Release lastMajor = this.getLastRelease(data, "major");
            Release lastMinor = this.getLastRelease(data, "minor");
            Release lastPatch = this.getLastRelease(data, "patch");

            String uuid = this.clusterService.state().metadata().clusterUUID();
            String lastCheckDate =
                    OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

            // Build the structured message object matching VersionCheckResponse format
            Map<String, Object> messageMap = new HashMap<>();
            messageMap.put("uuid", uuid);
            messageMap.put("last_check_date", lastCheckDate);
            messageMap.put("current_version", tag);
            messageMap.put("last_available_major", this.releaseToMap(lastMajor));
            messageMap.put("last_available_minor", this.releaseToMap(lastMinor));
            messageMap.put("last_available_patch", this.releaseToMap(lastPatch));

            // Serialize message as JSON string but pass parsed object for structured output
            String messageJson = this.mapper.writeValueAsString(messageMap);
            return new VersionCheckResponse(messageJson, RestStatus.OK, messageMap);
        } catch (Exception e) {
            log.error("Unexpected error during version check: {}", e.getMessage(), e);
            return new VersionCheckResponse(
                    Constants.E_500_CTI_UNREACHABLE, RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Returns the shared CTI client, starting it on first use. One client (and I/O reactor) serves
     * every check for the life of the node instead of one per request.
     */
    private synchronized ApiClient client() {
        if (this.closed) {
            throw new IllegalStateException("The version check service is closed");
        }
        if (this.client == null) {
            this.client = this.clientFactory.get();
        }
        return this.client;
    }

    /**
     * Stops the shared CTI client, if it was started, aborting any in-flight exchange so node
     * shutdown does not wait on CTI. No client is started after this.
     */
    @Override
    public synchronized void close() {
        this.closed = true;
        if (this.client != null) {
            this.client.close(CloseMode.IMMEDIATE);
            this.client = null;
        }
    }

    private Release getLastRelease(JsonNode data, String category) {
        if (data == null || !data.has(category)) {
            return null;
        }
        JsonNode array = data.get(category);
        if (!array.isArray() || array.isEmpty()) {
            return null;
        }
        try {
            List<Release> releases =
                    this.mapper.readValue(array.toString(), new TypeReference<List<Release>>() {});
            return releases.getLast();
        } catch (Exception e) {
            log.warn("Failed to parse {} releases: {}", category, e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> releaseToMap(Release release) {
        if (release == null) {
            return new HashMap<>();
        }
        return this.mapper.convertValue(release, Map.class);
    }
}
