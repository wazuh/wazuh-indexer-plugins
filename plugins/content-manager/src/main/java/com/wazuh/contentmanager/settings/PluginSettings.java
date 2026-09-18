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
package com.wazuh.contentmanager.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.wazuh.contentmanager.utils.Constants;
import org.jspecify.annotations.NonNull;

/** This class encapsulates configuration settings and constants for the Content Manager plugin. */
public class PluginSettings {
    private static final Logger log = LogManager.getLogger(PluginSettings.class);

    // Rest API endpoints
    public static final String PLUGINS_BASE_URI = "/_plugins/_content_manager";
    public static final String SUBSCRIPTION_URI = PLUGINS_BASE_URI + "/subscription";
    public static final String UPDATE_URI = PLUGINS_BASE_URI + "/update";
    public static final String LOGTEST_URI = PLUGINS_BASE_URI + "/logtest";
    public static final String LOGTEST_NORMALIZATION_URI = LOGTEST_URI + "/normalization";
    public static final String LOGTEST_DETECTION_URI = LOGTEST_URI + "/detection";
    public static final String KVDBS_URI = PLUGINS_BASE_URI + "/kvdbs";
    public static final String DECODERS_URI = PLUGINS_BASE_URI + "/decoders";
    public static final String RULES_URI = PLUGINS_BASE_URI + "/rules";
    public static final String INTEGRATIONS_URI = PLUGINS_BASE_URI + "/integrations";
    public static final String PROMOTE_URI = PLUGINS_BASE_URI + "/promote";
    public static final String POLICY_URI = PLUGINS_BASE_URI + "/policy";
    public static final String FILTERS_URI = PLUGINS_BASE_URI + "/filters";
    public static final String SPACE_URI = PLUGINS_BASE_URI + "/space";
    public static final String VERSION_CHECK_URI = PLUGINS_BASE_URI + "/version/check";

    /**
     * Name of the dedicated, bounded thread pool that executes logtest requests. Offloading logtest
     * off the transport thread and onto a fixed pool with a bounded queue prevents request
     * concurrency from being converted directly into heap pressure (overflow is rejected with 429).
     */
    public static final String LOGTEST_THREAD_POOL = "content_manager_logtest";

    /** Settings default values */
    private static final int DEFAULT_MAX_ITEMS_PER_BULK = 1000;

    public static final int DEFAULT_MAX_INTEGRATIONS = 100;
    private static final int MINIMUM_MAX_INTEGRATIONS = 0;

    public static final int DEFAULT_MAX_DECODERS = 200;
    private static final int MINIMUM_MAX_DECODERS = 0;

    public static final int DEFAULT_MAX_RULES = 200;
    private static final int MINIMUM_MAX_RULES = 0;

    public static final int DEFAULT_MAX_KVDBS = 100;
    private static final int MINIMUM_MAX_KVDBS = 0;

    public static final int DEFAULT_MAX_FILTERS = 100;
    private static final int MINIMUM_MAX_FILTERS = 0;

    private static final long DEFAULT_MAX_BULK_BYTES = 5L * 1024 * 1024;
    private static final long DEFAULT_LOGTEST_MAX_BODY_BYTES = 1L * 1024 * 1024;
    private static final int DEFAULT_MAX_CONCURRENT_BULKS = 5;
    private static final int DEFAULT_CLIENT_TIMEOUT = 10;
    private static final int DEFAULT_CATALOG_SYNC_INTERVAL = 60;
    private static final boolean DEFAULT_UPDATE_ON_START = true;
    private static final boolean DEFAULT_UPDATE_ON_SCHEDULE = true;
    private static final boolean DEFAULT_CREATE_DETECTORS = true;

    // Default values for catalog consumer URLs
    private static final String DEFAULT_CATALOG_RULESET = "";
    private static final String DEFAULT_CATALOG_IOCS = "";
    private static final String DEFAULT_CATALOG_VULNERABILITIES = "";

    private static final long DEFAULT_PIT_KEEPALIVE = 120;
    private static final boolean DEFAULT_ENGINE_MOCK_ENABLED = false;

    // Defaults for the Setup-plugin readiness wait in CatalogSyncJob#waitForSetup(). Worst-case
    // total wait before giving up is baseSeconds * (2^maxRetries - 1); the defaults (20s, 4 retries)
    // give 20+40+80+160 = 300s (5 min).
    private static final int DEFAULT_SETUP_WAIT_MAX_RETRIES = 4;
    private static final int DEFAULT_SETUP_WAIT_BACKOFF_BASE_SECONDS = 20;

    // Defaults for the CTI HTTP client 429 (Too Many Requests) retry loop in ApiClient. On a 429 the
    // client honors the server Retry-After header (in practice the CTI API asks for ~30-60s); only
    // when that header is absent does it fall back to exponential backoff (base * 2^attempt).
    private static final int DEFAULT_CLIENT_MAX_RETRIES = 3;
    private static final int DEFAULT_CLIENT_RETRY_BACKOFF_BASE_SECONDS = 30;

    // Defaults for the bulk retry policies in ContentIndex. A shed operation (circuit breaker trip,
    // indexing-pressure rejection, 429/503) sees pressure clear in seconds, so a short budget is
    // enough. A topology change (index recreated mid-load, shard left unavailable, node leaving)
    // has to outlast one full rolling restart, which scales with the size of the cluster.
    private static final int DEFAULT_BULK_SHED_MAX_RETRIES = 3;
    private static final long DEFAULT_BULK_SHED_INITIAL_BACKOFF_MILLIS = 1_000;
    private static final long DEFAULT_BULK_SHED_MAX_BACKOFF_MILLIS = 30_000;
    private static final int DEFAULT_BULK_TOPOLOGY_MAX_RETRIES = 5;
    private static final long DEFAULT_BULK_TOPOLOGY_INITIAL_BACKOFF_MILLIS = 5_000;
    private static final long DEFAULT_BULK_TOPOLOGY_MAX_BACKOFF_MILLIS = 30_000;

    // Defaults for the job-scheduler registration retry loop in ContentManagerPlugin, which uses
    // linear backoff (delay for attempt n is base * n).
    private static final int DEFAULT_JOB_SCHEDULE_MAX_RETRIES = 3;
    private static final int DEFAULT_JOB_SCHEDULE_RETRY_BACKOFF_SECONDS = 15;

    // Defaults for the resource-creation lock in ResourceLockService, which serializes the
    // count-then-create sequence enforcing the max_{integrations,decoders,rules,kvdbs,filters}
    // limits.
    private static final int DEFAULT_RESOURCE_LOCK_MAX_RETRIES = 20;
    private static final long DEFAULT_RESOURCE_LOCK_RETRY_BACKOFF_MILLIS = 100;
    private static final long DEFAULT_RESOURCE_LOCK_STALE_THRESHOLD_MILLIS = 30_000;

    // Defaults for the optimistic-concurrency retry loops on shared documents: the single
    // user-overrides registry document, and integration documents updated on resource link/unlink.
    private static final int DEFAULT_USER_OVERRIDES_MAX_UPDATE_ATTEMPTS = 3;
    private static final int DEFAULT_INTEGRATION_MAX_UPDATE_ATTEMPTS = 5;

    // Default timeout value for outbound CTI requests, in seconds.
    private static final int DEFAULT_CTI_API_TIMEOUT = 60;

    // Defaults for the Engine integration: the single-flight guard on a content reload, the grace
    // period before a read-not-ready deferral is escalated to a warning, and the Unix socket the
    // Engine listens on.
    private static final int DEFAULT_ENGINE_RELOAD_TIMEOUT_MINUTES = 10;
    private static final int DEFAULT_ENGINE_NOT_READY_GRACE_MINUTES = 5;
    private static final String DEFAULT_ENGINE_SOCKET_PATH =
            "/usr/share/wazuh-indexer/engine/sockets/engine-api-http.sock";

    // Defaults for the Security Analytics synchronization waits in ConsumerRulesetService, and for
    // the detector schedule interval applied when the CTI document does not carry one.
    private static final int DEFAULT_SA_SYNC_TIMEOUT_SECONDS = 60;
    private static final int DEFAULT_SA_DETECTOR_TIMEOUT_SECONDS = 30;
    private static final int DEFAULT_SA_CLEANUP_TIMEOUT_SECONDS = 120;
    private static final int DEFAULT_SA_DETECTOR_INTERVAL = 2;

    // Defaults for batching and paging during catalog synchronization.
    private static final int DEFAULT_UPDATE_SUB_BATCH_SIZE = 50;
    private static final int DEFAULT_OFFSET_FLUSH_INTERVAL = 10;
    private static final int DEFAULT_SEARCH_PAGE_SIZE = 10_000;

    private static final Pattern CATALOG_URI_PATTERN =
            Pattern.compile(".*/catalog/contexts/([^/]+)/consumers/([^/?#]+)(?:[/?#].*)?$");

    /** Singleton instance. */
    private static PluginSettings INSTANCE;

    /** Base Wazuh CTI URL */
    public static final String CTI_URL = "https://api.pre.cloud.wazuh.com/api/v1";

    /** The CTI API URL from the configuration file */
    public static final Setting<String> CTI_API_URL =
            Setting.simpleString(
                    "plugins.content_manager.cti.api",
                    CTI_URL,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Request timeout, in seconds, for CTI API calls. */
    public static final Setting<Integer> CTI_API_TIMEOUT =
            Setting.intSetting(
                    "plugins.content_manager.cti.api.timeout",
                    DEFAULT_CTI_API_TIMEOUT,
                    1,
                    120,
                    Setting.Property.NodeScope);

    /**
     * The maximum number of elements that are included in a bulk request during the initialization
     * from a snapshot.
     */
    public static final Setting<Integer> MAX_ITEMS_PER_BULK =
            Setting.intSetting(
                    "plugins.content_manager.max_items_per_bulk",
                    DEFAULT_MAX_ITEMS_PER_BULK,
                    10,
                    1000,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * The maximum estimated size, in bytes, of an accumulated bulk request before it is flushed
     * during the initialization from a snapshot. Bounds peak heap regardless of individual document
     * size (e.g. large CVE documents): worst-case in-flight payload is {@code MAX_CONCURRENT_BULKS *
     * MAX_BULK_BYTES}. The 100 MB ceiling stays under the OpenSearch default {@code
     * http.max_content_length}.
     */
    public static final Setting<Long> MAX_BULK_BYTES =
            Setting.longSetting(
                    "plugins.content_manager.max_bulk_bytes",
                    DEFAULT_MAX_BULK_BYTES,
                    1L * 1024 * 1024,
                    100L * 1024 * 1024,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Maximum size, in bytes, of a logtest request body ({@code POST
     * /_plugins/_content_manager/logtest} and its {@code /normalization} and {@code /detection}
     * siblings). A log line is at most a few kilobytes; the endpoint amplifies its input into the
     * response (~2 bytes out per byte in) and, being available to read-only accounts, is otherwise a
     * cheap way to exhaust the indexer's heap. Requests whose raw body exceeds this limit are
     * rejected with {@code 413 REQUEST_ENTITY_TOO_LARGE} at the REST layer, before parsing or
     * dispatch, so the amplification never happens. Default 1 MiB; bounded 1 KiB–16 MiB.
     */
    public static final Setting<Long> LOGTEST_MAX_BODY_BYTES =
            Setting.longSetting(
                    "plugins.content_manager.logtest.max_body_bytes",
                    DEFAULT_LOGTEST_MAX_BODY_BYTES,
                    1L * 1024,
                    16L * 1024 * 1024,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * The maximum number of co-existing bulk operations during the initialization from a snapshot.
     */
    public static final Setting<Integer> MAX_CONCURRENT_BULKS =
            Setting.intSetting(
                    "plugins.content_manager.max_concurrent_bulks",
                    DEFAULT_MAX_CONCURRENT_BULKS,
                    1,
                    5,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Timeout of indexing operations */
    public static final Setting<Long> CLIENT_TIMEOUT =
            Setting.longSetting(
                    "plugins.content_manager.client.timeout",
                    DEFAULT_CLIENT_TIMEOUT,
                    10,
                    50,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * The interval in minutes for the catalog synchronization job. Dynamic: a change is reflected in
     * the {@code wazuh-catalog-sync-job} document without restarting the node.
     */
    public static final Setting<Integer> CATALOG_SYNC_INTERVAL =
            Setting.intSetting(
                    "plugins.content_manager.catalog.sync_interval",
                    DEFAULT_CATALOG_SYNC_INTERVAL,
                    10,
                    1440,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /** Setting to trigger content update on start. */
    public static final Setting<Boolean> UPDATE_ON_START =
            Setting.boolSetting(
                    "plugins.content_manager.catalog.update_on_start",
                    DEFAULT_UPDATE_ON_START,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Setting to enable/disable the periodic catalog synchronization job. Dynamic: a change is
     * reflected in the {@code wazuh-catalog-sync-job} document without restarting the node.
     */
    public static final Setting<Boolean> UPDATE_ON_SCHEDULE =
            Setting.boolSetting(
                    "plugins.content_manager.catalog.update_on_schedule",
                    DEFAULT_UPDATE_ON_SCHEDULE,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /** Setting to enable/disable the content update job. */
    public static final Setting<Boolean> CREATE_DETECTORS =
            Setting.boolSetting(
                    "plugins.content_manager.catalog.create_detectors",
                    DEFAULT_CREATE_DETECTORS,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Full ruleset catalog consumer URL. */
    public static final Setting<String> CATALOG_RULESET =
            Setting.simpleString(
                    "plugins.content_manager.catalog.ruleset",
                    DEFAULT_CATALOG_RULESET,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Full IoCs catalog consumer URL. */
    public static final Setting<String> CATALOG_IOCS =
            Setting.simpleString(
                    "plugins.content_manager.catalog.iocs",
                    DEFAULT_CATALOG_IOCS,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Full vulnerabilities catalog consumer URL. */
    public static final Setting<String> CATALOG_VULNERABILITIES =
            Setting.simpleString(
                    "plugins.content_manager.catalog.vulnerabilities",
                    DEFAULT_CATALOG_VULNERABILITIES,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** PIT (Point-in-Time) keepalive duration in seconds for paginated searches. */
    public static final Setting<Long> PIT_KEEPALIVE =
            Setting.longSetting(
                    "plugins.content_manager.pit_keepalive",
                    DEFAULT_PIT_KEEPALIVE,
                    60,
                    600,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Maximum number of retries {@code CatalogSyncJob#waitForSetup()} performs while waiting for the
     * Setup plugin to report readiness, before giving up and deferring to the next scheduled sync.
     */
    public static final Setting<Integer> SETUP_WAIT_MAX_RETRIES =
            Setting.intSetting(
                    "plugins.content_manager.setup_wait.max_retries",
                    DEFAULT_SETUP_WAIT_MAX_RETRIES,
                    0,
                    10,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Base delay, in seconds, for the exponential backoff {@code CatalogSyncJob#waitForSetup()} uses
     * between retries (delay for retry {@code n} is {@code base * 2^n}).
     */
    public static final Setting<Integer> SETUP_WAIT_BACKOFF_BASE_SECONDS =
            Setting.intSetting(
                    "plugins.content_manager.setup_wait.backoff_base_seconds",
                    DEFAULT_SETUP_WAIT_BACKOFF_BASE_SECONDS,
                    1,
                    120,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Maximum number of retries the CTI HTTP client performs when the API responds with HTTP 429 (Too
     * Many Requests), before returning the 429 response to the caller.
     */
    public static final Setting<Integer> CLIENT_MAX_RETRIES =
            Setting.intSetting(
                    "plugins.content_manager.client.max_retries",
                    DEFAULT_CLIENT_MAX_RETRIES,
                    0,
                    10,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Base delay, in seconds, for the exponential backoff the CTI HTTP client uses between 429
     * retries when the response carries no usable Retry-After header (delay for retry {@code n} is
     * {@code base * 2^n}).
     */
    public static final Setting<Integer> CLIENT_RETRY_BACKOFF_BASE_SECONDS =
            Setting.intSetting(
                    "plugins.content_manager.client.retry_backoff_base_seconds",
                    DEFAULT_CLIENT_RETRY_BACKOFF_BASE_SECONDS,
                    1,
                    300,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Setting to enable mock engine service for testing environments. */
    public static final Setting<Boolean> ENGINE_MOCK_ENABLED =
            Setting.boolSetting(
                    "plugins.content_manager.engine.mock",
                    DEFAULT_ENGINE_MOCK_ENABLED,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Setting to enable the mock Security Analytics service for testing environments.
     *
     * <p>Separate from {@link #ENGINE_MOCK_ENABLED} because the two are not available under the same
     * conditions: the Engine talks over a Unix socket that a test cluster does not have, while
     * Security Analytics is a plugin this one extends and is therefore always installed. Defaults to
     * whatever the engine mock is set to, so an environment that mocked both keeps doing so, but a
     * test cluster can now mock only the Engine and exercise real rule evaluation.
     */
    public static final Setting<Boolean> SECURITY_ANALYTICS_MOCK_ENABLED =
            Setting.boolSetting(
                    "plugins.content_manager.security_analytics.mock",
                    ENGINE_MOCK_ENABLED,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /** Configuration setting to enable or disable the telemetry ping. Defaults to true. */
    public static final Setting<Boolean> TELEMETRY_ENABLED =
            Setting.boolSetting(
                    "plugins.content_manager.telemetry.enabled",
                    true,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Controls whether on-demand content updates can be triggered through the API ({@code POST
     * /_plugins/_content_manager/update}). When set to {@code false}, the endpoint returns {@code 403
     * FORBIDDEN} for every caller, regardless of role. Intended for externally managed (e.g. Wazuh
     * Cloud) deployments. Defaults to true.
     */
    public static final Setting<Boolean> UPDATE_ON_DEMAND =
            Setting.boolSetting(
                    "plugins.content_manager.catalog.update_on_demand",
                    true,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Controls whether policy updates can be performed through the API ({@code PUT
     * /_plugins/_content_manager/policy/{space}}). When set to {@code false}, the endpoint returns
     * {@code 403 FORBIDDEN} for every caller, regardless of role. Intended for externally managed
     * (e.g. Wazuh Cloud) deployments. Defaults to true.
     */
    public static final Setting<Boolean> POLICY_UPDATE_ENABLED =
            Setting.boolSetting(
                    "plugins.content_manager.catalog.policy_update.enabled",
                    true,
                    Setting.Property.NodeScope,
                    Setting.Property.Filtered);

    /**
     * Maximum number of user-created integrations allowed in the draft space. Requests that would
     * exceed this limit are rejected with a 400 error.
     */
    public static final Setting<Integer> MAX_INTEGRATIONS =
            Setting.intSetting(
                    "plugins.content_manager.max_integrations",
                    DEFAULT_MAX_INTEGRATIONS,
                    MINIMUM_MAX_INTEGRATIONS,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of user-created decoders allowed in the draft space. Requests that would exceed
     * this limit are rejected with a 400 error.
     */
    public static final Setting<Integer> MAX_DECODERS =
            Setting.intSetting(
                    "plugins.content_manager.max_decoders",
                    DEFAULT_MAX_DECODERS,
                    MINIMUM_MAX_DECODERS,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of user-created rules allowed in the draft space. Requests that would exceed
     * this limit are rejected with a 400 error.
     */
    public static final Setting<Integer> MAX_RULES =
            Setting.intSetting(
                    "plugins.content_manager.max_rules",
                    DEFAULT_MAX_RULES,
                    MINIMUM_MAX_RULES,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of user-created kvdbs allowed in the draft space. Requests that would exceed
     * this limit are rejected with a 400 error.
     */
    public static final Setting<Integer> MAX_KVDBS =
            Setting.intSetting(
                    "plugins.content_manager.max_kvdbs",
                    DEFAULT_MAX_KVDBS,
                    MINIMUM_MAX_KVDBS,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of user-created filters allowed per space. Requests that would exceed this limit
     * are rejected with a 400 error.
     */
    public static final Setting<Integer> MAX_FILTERS =
            Setting.intSetting(
                    "plugins.content_manager.max_filters",
                    DEFAULT_MAX_FILTERS,
                    MINIMUM_MAX_FILTERS,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of times a bulk operation the cluster shed under load (circuit breaker trip,
     * indexing-pressure rejection, 429/503) is re-submitted before its documents are counted as
     * dropped. Dynamic: pressure that outlasts the default budget is discovered during an incident,
     * not at configuration time.
     */
    public static final Setting<Integer> BULK_SHED_MAX_RETRIES =
            Setting.intSetting(
                    "plugins.content_manager.bulk.retry.shed.max_retries",
                    DEFAULT_BULK_SHED_MAX_RETRIES,
                    0,
                    20,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Delay, in milliseconds, before the first re-submission of a shed bulk operation. Each
     * subsequent retry doubles it, capped at {@link #BULK_SHED_MAX_BACKOFF_MILLIS}.
     */
    public static final Setting<Long> BULK_SHED_INITIAL_BACKOFF_MILLIS =
            Setting.longSetting(
                    "plugins.content_manager.bulk.retry.shed.initial_backoff_millis",
                    DEFAULT_BULK_SHED_INITIAL_BACKOFF_MILLIS,
                    100,
                    600_000,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /** Ceiling, in milliseconds, for the exponential backoff between shed bulk re-submissions. */
    public static final Setting<Long> BULK_SHED_MAX_BACKOFF_MILLIS =
            Setting.longSetting(
                    "plugins.content_manager.bulk.retry.shed.max_backoff_millis",
                    DEFAULT_BULK_SHED_MAX_BACKOFF_MILLIS,
                    100,
                    600_000,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of times a bulk operation deferred by a transient cluster-topology change (an
     * index recreated mid-load, a shard left unavailable, the node holding it leaving) is
     * re-submitted before its documents are counted as dropped. The default budget was sized to
     * outlast one rolling restart; raise it on clusters where a restart takes longer.
     */
    public static final Setting<Integer> BULK_TOPOLOGY_MAX_RETRIES =
            Setting.intSetting(
                    "plugins.content_manager.bulk.retry.topology.max_retries",
                    DEFAULT_BULK_TOPOLOGY_MAX_RETRIES,
                    0,
                    20,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Delay, in milliseconds, before the first re-submission of a topology-deferred bulk operation.
     * Each subsequent retry doubles it, capped at {@link #BULK_TOPOLOGY_MAX_BACKOFF_MILLIS}.
     */
    public static final Setting<Long> BULK_TOPOLOGY_INITIAL_BACKOFF_MILLIS =
            Setting.longSetting(
                    "plugins.content_manager.bulk.retry.topology.initial_backoff_millis",
                    DEFAULT_BULK_TOPOLOGY_INITIAL_BACKOFF_MILLIS,
                    100,
                    600_000,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Ceiling, in milliseconds, for the exponential backoff between topology-deferred bulk
     * re-submissions.
     */
    public static final Setting<Long> BULK_TOPOLOGY_MAX_BACKOFF_MILLIS =
            Setting.longSetting(
                    "plugins.content_manager.bulk.retry.topology.max_backoff_millis",
                    DEFAULT_BULK_TOPOLOGY_MAX_BACKOFF_MILLIS,
                    100,
                    600_000,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of attempts to register a periodic job with the job scheduler before giving up
     * and logging an error.
     */
    public static final Setting<Integer> JOB_SCHEDULE_MAX_RETRIES =
            Setting.intSetting(
                    "plugins.content_manager.job_schedule.max_retries",
                    DEFAULT_JOB_SCHEDULE_MAX_RETRIES,
                    0,
                    10,
                    Setting.Property.NodeScope);

    /**
     * Base delay, in seconds, for the linear backoff between job-registration attempts (delay before
     * attempt {@code n} is {@code base * n}).
     */
    public static final Setting<Integer> JOB_SCHEDULE_RETRY_BACKOFF_SECONDS =
            Setting.intSetting(
                    "plugins.content_manager.job_schedule.retry_backoff_seconds",
                    DEFAULT_JOB_SCHEDULE_RETRY_BACKOFF_SECONDS,
                    1,
                    300,
                    Setting.Property.NodeScope);

    /**
     * Maximum number of attempts to acquire the resource-creation lock before the request is rejected
     * with {@code 503 SERVICE_UNAVAILABLE}.
     */
    public static final Setting<Integer> RESOURCE_LOCK_MAX_RETRIES =
            Setting.intSetting(
                    "plugins.content_manager.resource_lock.max_retries",
                    DEFAULT_RESOURCE_LOCK_MAX_RETRIES,
                    1,
                    100,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /** Delay, in milliseconds, between resource-creation lock acquisition attempts. */
    public static final Setting<Long> RESOURCE_LOCK_RETRY_BACKOFF_MILLIS =
            Setting.longSetting(
                    "plugins.content_manager.resource_lock.retry_backoff_millis",
                    DEFAULT_RESOURCE_LOCK_RETRY_BACKOFF_MILLIS,
                    10,
                    10_000,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Age, in milliseconds, past which a held resource-creation lock is treated as orphaned by a
     * crashed node and stolen by the next caller.
     */
    public static final Setting<Long> RESOURCE_LOCK_STALE_THRESHOLD_MILLIS =
            Setting.longSetting(
                    "plugins.content_manager.resource_lock.stale_threshold_millis",
                    DEFAULT_RESOURCE_LOCK_STALE_THRESHOLD_MILLIS,
                    1_000,
                    600_000,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of attempts to write the shared user-overrides registry document before giving
     * up. The registry is one document, so concurrent writers are serialized optimistically and each
     * version conflict re-reads and re-applies.
     */
    public static final Setting<Integer> USER_OVERRIDES_MAX_UPDATE_ATTEMPTS =
            Setting.intSetting(
                    "plugins.content_manager.user_overrides.max_update_attempts",
                    DEFAULT_USER_OVERRIDES_MAX_UPDATE_ATTEMPTS,
                    1,
                    20,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of attempts to update an integration document on a version conflict, when
     * linking or unlinking a resource, before the operation fails.
     */
    public static final Setting<Integer> INTEGRATION_MAX_UPDATE_ATTEMPTS =
            Setting.intSetting(
                    "plugins.content_manager.integration.max_update_attempts",
                    DEFAULT_INTEGRATION_MAX_UPDATE_ATTEMPTS,
                    1,
                    20,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Upper bound, in minutes, on how long a single Engine content reload may stay in flight. It
     * guards against a lost callback wedging the single-flight guard forever.
     */
    public static final Setting<Integer> ENGINE_RELOAD_TIMEOUT_MINUTES =
            Setting.intSetting(
                    "plugins.content_manager.engine.reload_timeout_minutes",
                    DEFAULT_ENGINE_RELOAD_TIMEOUT_MINUTES,
                    1,
                    1440,
                    Setting.Property.NodeScope);

    /**
     * How long, in minutes, the content indices may stay unable to serve reads before the deferral is
     * escalated from a debug line to a warning.
     */
    public static final Setting<Integer> ENGINE_NOT_READY_GRACE_MINUTES =
            Setting.intSetting(
                    "plugins.content_manager.engine.not_ready_grace_minutes",
                    DEFAULT_ENGINE_NOT_READY_GRACE_MINUTES,
                    1,
                    1440,
                    Setting.Property.NodeScope);

    /** Filesystem path of the Unix domain socket the Engine API listens on. */
    public static final Setting<String> ENGINE_SOCKET_PATH =
            Setting.simpleString(
                    "plugins.content_manager.engine.socket_path",
                    DEFAULT_ENGINE_SOCKET_PATH,
                    Setting.Property.NodeScope);

    /**
     * How long, in seconds, a Security Analytics bulk synchronization step (uploading rules or
     * integrations) may run before it is abandoned and the pass reported as unsuccessful.
     */
    public static final Setting<Integer> SA_SYNC_TIMEOUT_SECONDS =
            Setting.intSetting(
                    "plugins.content_manager.security_analytics.sync_timeout_seconds",
                    DEFAULT_SA_SYNC_TIMEOUT_SECONDS,
                    1,
                    3600,
                    Setting.Property.NodeScope);

    /** How long, in seconds, to wait for the first detector creation to complete. */
    public static final Setting<Integer> SA_DETECTOR_TIMEOUT_SECONDS =
            Setting.intSetting(
                    "plugins.content_manager.security_analytics.detector_timeout_seconds",
                    DEFAULT_SA_DETECTOR_TIMEOUT_SECONDS,
                    1,
                    3600,
                    Setting.Property.NodeScope);

    /**
     * How long, in seconds, to wait for the deletion of stale Security Analytics rules and
     * integrations after a content swap.
     */
    public static final Setting<Integer> SA_CLEANUP_TIMEOUT_SECONDS =
            Setting.intSetting(
                    "plugins.content_manager.security_analytics.cleanup_timeout_seconds",
                    DEFAULT_SA_CLEANUP_TIMEOUT_SECONDS,
                    1,
                    3600,
                    Setting.Property.NodeScope);

    /**
     * Detector schedule interval, in minutes, applied when the CTI integration document does not
     * specify one, or specifies one outside the bounds Security Analytics accepts.
     */
    public static final Setting<Integer> SA_DETECTOR_INTERVAL =
            Setting.intSetting(
                    "plugins.content_manager.security_analytics.detector_interval",
                    DEFAULT_SA_DETECTOR_INTERVAL,
                    Constants.DETECTOR_INTERVAL_MIN_MINUTES,
                    Constants.DETECTOR_INTERVAL_MAX_MINUTES,
                    Setting.Property.NodeScope,
                    Setting.Property.Dynamic);

    /**
     * Maximum number of UPDATE offsets batched into a single MultiGet + BulkRequest while applying a
     * catalog changeset.
     */
    public static final Setting<Integer> UPDATE_SUB_BATCH_SIZE =
            Setting.intSetting(
                    "plugins.content_manager.update_sub_batch_size",
                    DEFAULT_UPDATE_SUB_BATCH_SIZE,
                    1,
                    1000,
                    Setting.Property.NodeScope);

    /**
     * How many batches (changeset application) or bulks (snapshot load) are processed between
     * consumer-offset checkpoints. A smaller value narrows the window of work replayed after a crash,
     * at the cost of more writes to the consumer-state document.
     */
    public static final Setting<Integer> OFFSET_FLUSH_INTERVAL =
            Setting.intSetting(
                    "plugins.content_manager.offset_flush_interval",
                    DEFAULT_OFFSET_FLUSH_INTERVAL,
                    1,
                    1000,
                    Setting.Property.NodeScope);

    /**
     * Page size used by the internal paginated searches that enumerate content documents (space
     * membership, IoC reconciliation, detector lookup).
     */
    public static final Setting<Integer> SEARCH_PAGE_SIZE =
            Setting.intSetting(
                    "plugins.content_manager.search_page_size",
                    DEFAULT_SEARCH_PAGE_SIZE,
                    100,
                    10_000,
                    Setting.Property.NodeScope);

    private final String ctiBaseUrl;
    private final int ctiRequestTimeout;
    private final int maximumItemsPerBulk;
    private final long maximumBulkBytes;
    private volatile long logtestMaxBodyBytes;
    private final int maximumConcurrentBulks;
    private final long clientTimeout;
    private volatile int catalogSyncInterval;
    private final boolean updateOnStart;
    private volatile boolean updateOnSchedule;
    private final String catalogRuleset;
    private final String catalogIocs;
    private final String catalogVulnerabilities;
    private final long pitKeepalive;
    private final boolean engineMockEnabled;
    private final boolean securityAnalyticsMockEnabled;
    private final int setupWaitMaxRetries;
    private final int setupWaitBackoffBaseSeconds;
    private final int clientMaxRetries;
    private final int clientRetryBackoffBaseSeconds;
    private final boolean createDetectors;
    private final boolean updateOnDemand;
    private final boolean policyUpdateEnabled;
    private volatile boolean isTelemetryEnabled;
    private volatile int maxIntegrations;
    private volatile int maxDecoders;
    private volatile int maxRules;
    private volatile int maxKvdbs;
    private volatile int maxFilters;
    private volatile int bulkShedMaxRetries;
    private volatile long bulkShedInitialBackoffMillis;
    private volatile long bulkShedMaxBackoffMillis;
    private volatile int bulkTopologyMaxRetries;
    private volatile long bulkTopologyInitialBackoffMillis;
    private volatile long bulkTopologyMaxBackoffMillis;
    private final int jobScheduleMaxRetries;
    private final int jobScheduleRetryBackoffSeconds;
    private volatile int resourceLockMaxRetries;
    private volatile long resourceLockRetryBackoffMillis;
    private volatile long resourceLockStaleThresholdMillis;
    private volatile int userOverridesMaxUpdateAttempts;
    private volatile int integrationMaxUpdateAttempts;
    private final int engineReloadTimeoutMinutes;
    private final int engineNotReadyGraceMinutes;
    private final String engineSocketPath;
    private final int saSyncTimeoutSeconds;
    private final int saDetectorTimeoutSeconds;
    private final int saCleanupTimeoutSeconds;
    private volatile int saDetectorInterval;
    private final int updateSubBatchSize;
    private final int offsetFlushInterval;
    private final int searchPageSize;
    private volatile String accessToken;
    private volatile String clusterUUID;
    private String version;

    /**
     * Private default constructor
     *
     * @param settings as obtained in createComponents.
     */
    private PluginSettings(@NonNull final Settings settings) {
        this.ctiBaseUrl = CTI_API_URL.get(settings);
        this.maximumItemsPerBulk = MAX_ITEMS_PER_BULK.get(settings);
        this.maximumBulkBytes = MAX_BULK_BYTES.get(settings);
        this.logtestMaxBodyBytes = LOGTEST_MAX_BODY_BYTES.get(settings);
        this.maximumConcurrentBulks = MAX_CONCURRENT_BULKS.get(settings);
        this.clientTimeout = CLIENT_TIMEOUT.get(settings);
        this.catalogSyncInterval = CATALOG_SYNC_INTERVAL.get(settings);
        this.updateOnStart = UPDATE_ON_START.get(settings);
        this.updateOnSchedule = UPDATE_ON_SCHEDULE.get(settings);
        this.catalogRuleset = CATALOG_RULESET.get(settings);
        this.catalogIocs = CATALOG_IOCS.get(settings);
        this.catalogVulnerabilities = CATALOG_VULNERABILITIES.get(settings);
        this.pitKeepalive = PIT_KEEPALIVE.get(settings);
        this.engineMockEnabled = ENGINE_MOCK_ENABLED.get(settings);
        this.securityAnalyticsMockEnabled = SECURITY_ANALYTICS_MOCK_ENABLED.get(settings);
        this.setupWaitMaxRetries = SETUP_WAIT_MAX_RETRIES.get(settings);
        this.setupWaitBackoffBaseSeconds = SETUP_WAIT_BACKOFF_BASE_SECONDS.get(settings);
        this.clientMaxRetries = CLIENT_MAX_RETRIES.get(settings);
        this.clientRetryBackoffBaseSeconds = CLIENT_RETRY_BACKOFF_BASE_SECONDS.get(settings);
        this.createDetectors = CREATE_DETECTORS.get(settings);
        this.updateOnDemand = UPDATE_ON_DEMAND.get(settings);
        this.policyUpdateEnabled = POLICY_UPDATE_ENABLED.get(settings);
        this.isTelemetryEnabled = TELEMETRY_ENABLED.get(settings);
        this.maxIntegrations = MAX_INTEGRATIONS.get(settings);
        this.maxDecoders = MAX_DECODERS.get(settings);
        this.maxRules = MAX_RULES.get(settings);
        this.maxKvdbs = MAX_KVDBS.get(settings);
        this.maxFilters = MAX_FILTERS.get(settings);
        this.bulkShedMaxRetries = BULK_SHED_MAX_RETRIES.get(settings);
        this.bulkShedInitialBackoffMillis = BULK_SHED_INITIAL_BACKOFF_MILLIS.get(settings);
        this.bulkShedMaxBackoffMillis = BULK_SHED_MAX_BACKOFF_MILLIS.get(settings);
        this.bulkTopologyMaxRetries = BULK_TOPOLOGY_MAX_RETRIES.get(settings);
        this.bulkTopologyInitialBackoffMillis = BULK_TOPOLOGY_INITIAL_BACKOFF_MILLIS.get(settings);
        this.bulkTopologyMaxBackoffMillis = BULK_TOPOLOGY_MAX_BACKOFF_MILLIS.get(settings);
        this.jobScheduleMaxRetries = JOB_SCHEDULE_MAX_RETRIES.get(settings);
        this.jobScheduleRetryBackoffSeconds = JOB_SCHEDULE_RETRY_BACKOFF_SECONDS.get(settings);
        this.resourceLockMaxRetries = RESOURCE_LOCK_MAX_RETRIES.get(settings);
        this.resourceLockRetryBackoffMillis = RESOURCE_LOCK_RETRY_BACKOFF_MILLIS.get(settings);
        this.resourceLockStaleThresholdMillis = RESOURCE_LOCK_STALE_THRESHOLD_MILLIS.get(settings);
        this.userOverridesMaxUpdateAttempts = USER_OVERRIDES_MAX_UPDATE_ATTEMPTS.get(settings);
        this.integrationMaxUpdateAttempts = INTEGRATION_MAX_UPDATE_ATTEMPTS.get(settings);
        this.ctiRequestTimeout = CTI_API_TIMEOUT.get(settings);
        this.engineReloadTimeoutMinutes = ENGINE_RELOAD_TIMEOUT_MINUTES.get(settings);
        this.engineNotReadyGraceMinutes = ENGINE_NOT_READY_GRACE_MINUTES.get(settings);
        this.engineSocketPath = ENGINE_SOCKET_PATH.get(settings);
        this.saSyncTimeoutSeconds = SA_SYNC_TIMEOUT_SECONDS.get(settings);
        this.saDetectorTimeoutSeconds = SA_DETECTOR_TIMEOUT_SECONDS.get(settings);
        this.saCleanupTimeoutSeconds = SA_CLEANUP_TIMEOUT_SECONDS.get(settings);
        this.saDetectorInterval = SA_DETECTOR_INTERVAL.get(settings);
        this.updateSubBatchSize = UPDATE_SUB_BATCH_SIZE.get(settings);
        this.offsetFlushInterval = OFFSET_FLUSH_INTERVAL.get(settings);
        this.searchPageSize = SEARCH_PAGE_SIZE.get(settings);
        log.debug("Settings loaded: {}", this.toString());
    }

    /**
     * Singleton instance accessor. Initializes the settings
     *
     * @param settings as obtained in createComponents.
     * @return {@link PluginSettings#INSTANCE}
     */
    public static synchronized PluginSettings getInstance(@NonNull final Settings settings) {
        if (INSTANCE == null) {
            INSTANCE = new PluginSettings(settings);
        }
        return INSTANCE;
    }

    /**
     * Singleton instance accessor
     *
     * @return {@link PluginSettings#INSTANCE}
     * @throws IllegalStateException if the instance has not been initialized
     * @see PluginSettings#getInstance(Settings)
     */
    public static synchronized PluginSettings getInstance() {
        if (PluginSettings.INSTANCE == null) {
            throw new IllegalStateException("Plugin settings have not been initialized.");
        }
        return INSTANCE;
    }

    /**
     * Resets the singleton instance. Intended for use in unit tests only.
     *
     * <p><strong>WARNING:</strong> Do not call this method in production code.
     */
    public static synchronized void resetForTesting() {
        INSTANCE = null;
    }

    public void setTelemetryEnabled(boolean isTelemetryEnabled) {
        this.isTelemetryEnabled = isTelemetryEnabled;
    }

    public int getMaxIntegrations() {
        return this.maxIntegrations;
    }

    public void setMaxIntegrations(int maxIntegrations) {
        this.maxIntegrations = maxIntegrations;
    }

    public int getMaxDecoders() {
        return this.maxDecoders;
    }

    public void setMaxDecoders(int maxDecoders) {
        this.maxDecoders = maxDecoders;
    }

    public int getMaxRules() {
        return this.maxRules;
    }

    public void setMaxRules(int maxRules) {
        this.maxRules = maxRules;
    }

    public int getMaxKvdbs() {
        return this.maxKvdbs;
    }

    public void setMaxKvdbs(int maxKvdbs) {
        this.maxKvdbs = maxKvdbs;
    }

    public int getMaxFilters() {
        return this.maxFilters;
    }

    public void setMaxFilters(int maxFilters) {
        this.maxFilters = maxFilters;
    }

    /**
     * Sets the CTI access token.
     *
     * @param accessToken the access token string, or null to clear it.
     */
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * Retrieves the CTI access token.
     *
     * @return the access token string, or null if not set.
     */
    public String getAccessToken() {
        return this.accessToken;
    }

    /**
     * Returns whether this instance is registered in the Wazuh CTI Platform. A registered instance
     * has a non-null, non-blank access token.
     *
     * @return true if the instance is registered, false otherwise.
     */
    public boolean isRegistered() {
        return this.accessToken != null && !this.accessToken.isBlank();
    }

    /**
     * Sets the cluster UUID used as the wazuh-uid header in CTI API requests.
     *
     * @param clusterUUID the cluster UUID string, or null to clear it.
     */
    public void setClusterUUID(String clusterUUID) {
        this.clusterUUID = clusterUUID;
    }

    /**
     * Retrieves the cluster UUID used as the wazuh-uid header.
     *
     * @return the cluster UUID string, or null if not yet set.
     */
    public String getClusterUUID() {
        return this.clusterUUID;
    }

    /**
     * Sets the version of Wazuh. Should be called once during plugin initialization.
     *
     * @param version the Wazuh version string (e.g., "5.0.0").
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Retrieves the version of Wazuh.
     *
     * @return the Wazuh version string, or null if not set.
     */
    public String getVersion() {
        return this.version;
    }

    /**
     * Builds the custom user-agent string for CTI API communications.
     *
     * @return the user-agent string in the format "Wazuh Indexer {version}".
     */
    public String getUserAgent() {
        String version = this.version != null ? this.version : "unknown";
        return Constants.USER_AGENT_PREFIX + version;
    }

    /**
     * Getter method for the CTI API URL
     *
     * @return a string with the base URL
     */
    public String getCtiBaseUrl() {
        return this.ctiBaseUrl;
    }

    /**
     * Retrieves the maximum number of documents that can be indexed.
     *
     * @return an Integer representing the maximum number of documents allowed for content indexing.
     */
    public Integer getMaxItemsPerBulk() {
        return this.maximumItemsPerBulk;
    }

    /**
     * Retrieves the maximum estimated size, in bytes, of an accumulated bulk request before it is
     * flushed during snapshot indexing.
     *
     * @return a long representing the maximum bulk request size in bytes.
     */
    public long getMaxBulkBytes() {
        return this.maximumBulkBytes;
    }

    /**
     * Retrieves the maximum allowed size, in bytes, of a logtest request body.
     *
     * @return the maximum logtest request body size in bytes.
     */
    public long getLogtestMaxBodyBytes() {
        return this.logtestMaxBodyBytes;
    }

    /**
     * Updates the maximum allowed logtest request body size. Invoked by the cluster-settings update
     * consumer when {@code plugins.content_manager.logtest.max_body_bytes} changes.
     *
     * @param logtestMaxBodyBytes the new maximum size in bytes.
     */
    public void setLogtestMaxBodyBytes(long logtestMaxBodyBytes) {
        this.logtestMaxBodyBytes = logtestMaxBodyBytes;
    }

    /**
     * Retrieves the maximum number of concurrent petitions allowed for content indexing.
     *
     * @return an Integer representing the maximum number of concurrent petitions.
     */
    public Integer getMaximumConcurrentBulks() {
        return this.maximumConcurrentBulks;
    }

    /**
     * Retrieves the timeout value for content and context indexing operations.
     *
     * @return a Long representing the timeout duration in seconds.
     */
    public Long getClientTimeout() {
        return this.clientTimeout;
    }

    /**
     * Retrieves the interval in minutes for the catalog synchronization job.
     *
     * @return an Integer representing the interval in minutes.
     */
    public Integer getCatalogSyncInterval() {
        return this.catalogSyncInterval;
    }

    /**
     * Updates the catalog synchronization interval. Invoked by the cluster settings update consumer
     * registered for {@link #CATALOG_SYNC_INTERVAL}.
     *
     * @param catalogSyncInterval the new interval, in minutes.
     */
    public void setCatalogSyncInterval(int catalogSyncInterval) {
        this.catalogSyncInterval = catalogSyncInterval;
    }

    /**
     * Retrieves the value for the update on start setting.
     *
     * @return a Boolean indicating if the update on start is enabled.
     */
    public Boolean isUpdateOnStart() {
        return this.updateOnStart;
    }

    /**
     * Retrieves the value for the update on schedule setting.
     *
     * @return a Boolean indicating if the scheduled update is enabled.
     */
    public Boolean isUpdateOnSchedule() {
        return this.updateOnSchedule;
    }

    /**
     * Enables or disables the periodic catalog synchronization job. Invoked by the cluster settings
     * update consumer registered for {@link #UPDATE_ON_SCHEDULE}.
     *
     * @param updateOnSchedule true to enable the scheduled synchronization, false to disable it.
     */
    public void setUpdateOnSchedule(boolean updateOnSchedule) {
        this.updateOnSchedule = updateOnSchedule;
    }

    /**
     * Retrieves the value for the update on schedule setting.
     *
     * @return a Boolean indicating if the scheduled update is enabled.
     */
    public Boolean isTelemetryEnabled() {
        return this.isTelemetryEnabled;
    }

    /** Retrieves the full ruleset catalog consumer URL. */
    public String getCatalogRuleset() {
        return this.catalogRuleset;
    }

    /**
     * Returns whether on-demand content updates can be triggered through the API.
     *
     * @return true if on-demand content updates are enabled, false otherwise.
     */
    public boolean isUpdateOnDemandEnabled() {
        return this.updateOnDemand;
    }

    /**
     * Returns whether policy updates can be performed through the API.
     *
     * @return true if policy updates are enabled, false otherwise.
     */
    public boolean isPolicyUpdateEnabled() {
        return this.policyUpdateEnabled;
    }

    /**
     * Retrieves the Content Consumer.
     *
     * @return the consumer string.
     */
    public boolean getCreateDetectors() {
        return this.createDetectors;
    }

    /** Retrieves the full IoCs catalog consumer URL. */
    public String getCatalogIocs() {
        return this.catalogIocs;
    }

    /** Retrieves the full vulnerabilities catalog consumer URL. */
    public String getCatalogVulnerabilities() {
        return this.catalogVulnerabilities;
    }

    /**
     * Extracts the context segment from a consumer URL.
     *
     * @param catalogUri full consumer URL.
     * @return context value, or an empty string when the URL does not match the expected format.
     */
    public static String getContextFromCatalogUri(String catalogUri) {
        return PluginSettings.getCatalogUriPart(catalogUri, 1);
    }

    /**
     * Extracts the consumer segment from a consumer URL.
     *
     * @param catalogUri full consumer URL.
     * @return consumer value, or an empty string when the URL does not match the expected format.
     */
    public static String getConsumerFromCatalogUri(String catalogUri) {
        return PluginSettings.getCatalogUriPart(catalogUri, 2);
    }

    private static String getCatalogUriPart(String catalogUri, int group) {
        if (catalogUri == null || catalogUri.isBlank()) {
            return "";
        }

        Matcher matcher = CATALOG_URI_PATTERN.matcher(catalogUri);
        if (matcher.matches()) {
            return matcher.group(group);
        }

        return "";
    }

    /**
     * Retrieves the PIT (Point-in-Time) keepalive duration in seconds.
     *
     * @return the keepalive duration in seconds.
     */
    public Long getPitKeepalive() {
        return this.pitKeepalive;
    }

    /**
     * Retrieves the value for the engine mock enabled setting.
     *
     * @return a Boolean indicating if the mock engine service is enabled.
     */
    public Boolean isEngineMockEnabled() {
        return this.engineMockEnabled;
    }

    /**
     * Retrieves the value for the Security Analytics mock enabled setting.
     *
     * @return a Boolean indicating if the mock Security Analytics service is enabled.
     */
    public Boolean isSecurityAnalyticsMockEnabled() {
        return this.securityAnalyticsMockEnabled;
    }

    /**
     * Retrieves the maximum number of retries {@code CatalogSyncJob#waitForSetup()} performs while
     * waiting for the Setup plugin to report readiness.
     *
     * @return the maximum number of retries.
     */
    public int getSetupWaitMaxRetries() {
        return this.setupWaitMaxRetries;
    }

    /**
     * Retrieves the base delay, in seconds, for the exponential backoff {@code
     * CatalogSyncJob#waitForSetup()} uses between retries.
     *
     * @return the base backoff delay in seconds.
     */
    public int getSetupWaitBackoffBaseSeconds() {
        return this.setupWaitBackoffBaseSeconds;
    }

    /**
     * Retrieves the maximum number of 429 retries the CTI HTTP client performs.
     *
     * @return the maximum number of retries.
     */
    public int getClientMaxRetries() {
        return this.clientMaxRetries;
    }

    /**
     * Retrieves the base delay, in seconds, for the CTI HTTP client's 429 exponential-backoff
     * fallback.
     *
     * @return the base backoff delay in seconds.
     */
    public int getClientRetryBackoffBaseSeconds() {
        return this.clientRetryBackoffBaseSeconds;
    }

    /**
     * Retrieves the maximum number of re-submissions of a bulk operation the cluster shed under load.
     *
     * @return the maximum number of retries.
     */
    public int getBulkShedMaxRetries() {
        return this.bulkShedMaxRetries;
    }

    /**
     * Updates the shed bulk retry budget. Invoked by the cluster-settings update consumer registered
     * for {@link #BULK_SHED_MAX_RETRIES}.
     *
     * @param bulkShedMaxRetries the new maximum number of retries.
     */
    public void setBulkShedMaxRetries(int bulkShedMaxRetries) {
        this.bulkShedMaxRetries = bulkShedMaxRetries;
    }

    /**
     * Retrieves the initial backoff, in milliseconds, between shed bulk re-submissions.
     *
     * @return the initial backoff in milliseconds.
     */
    public long getBulkShedInitialBackoffMillis() {
        return this.bulkShedInitialBackoffMillis;
    }

    /**
     * Updates the initial shed bulk backoff. Invoked by the cluster-settings update consumer
     * registered for {@link #BULK_SHED_INITIAL_BACKOFF_MILLIS}.
     *
     * @param bulkShedInitialBackoffMillis the new initial backoff in milliseconds.
     */
    public void setBulkShedInitialBackoffMillis(long bulkShedInitialBackoffMillis) {
        this.bulkShedInitialBackoffMillis = bulkShedInitialBackoffMillis;
    }

    /**
     * Retrieves the backoff ceiling, in milliseconds, for shed bulk re-submissions.
     *
     * @return the maximum backoff in milliseconds.
     */
    public long getBulkShedMaxBackoffMillis() {
        return this.bulkShedMaxBackoffMillis;
    }

    /**
     * Updates the shed bulk backoff ceiling. Invoked by the cluster-settings update consumer
     * registered for {@link #BULK_SHED_MAX_BACKOFF_MILLIS}.
     *
     * @param bulkShedMaxBackoffMillis the new maximum backoff in milliseconds.
     */
    public void setBulkShedMaxBackoffMillis(long bulkShedMaxBackoffMillis) {
        this.bulkShedMaxBackoffMillis = bulkShedMaxBackoffMillis;
    }

    /**
     * Retrieves the maximum number of re-submissions of a bulk operation deferred by a transient
     * cluster-topology change.
     *
     * @return the maximum number of retries.
     */
    public int getBulkTopologyMaxRetries() {
        return this.bulkTopologyMaxRetries;
    }

    /**
     * Updates the topology bulk retry budget. Invoked by the cluster-settings update consumer
     * registered for {@link #BULK_TOPOLOGY_MAX_RETRIES}.
     *
     * @param bulkTopologyMaxRetries the new maximum number of retries.
     */
    public void setBulkTopologyMaxRetries(int bulkTopologyMaxRetries) {
        this.bulkTopologyMaxRetries = bulkTopologyMaxRetries;
    }

    /**
     * Retrieves the initial backoff, in milliseconds, between topology-deferred bulk re-submissions.
     *
     * @return the initial backoff in milliseconds.
     */
    public long getBulkTopologyInitialBackoffMillis() {
        return this.bulkTopologyInitialBackoffMillis;
    }

    /**
     * Updates the initial topology bulk backoff. Invoked by the cluster-settings update consumer
     * registered for {@link #BULK_TOPOLOGY_INITIAL_BACKOFF_MILLIS}.
     *
     * @param bulkTopologyInitialBackoffMillis the new initial backoff in milliseconds.
     */
    public void setBulkTopologyInitialBackoffMillis(long bulkTopologyInitialBackoffMillis) {
        this.bulkTopologyInitialBackoffMillis = bulkTopologyInitialBackoffMillis;
    }

    /**
     * Retrieves the backoff ceiling, in milliseconds, for topology-deferred bulk re-submissions.
     *
     * @return the maximum backoff in milliseconds.
     */
    public long getBulkTopologyMaxBackoffMillis() {
        return this.bulkTopologyMaxBackoffMillis;
    }

    /**
     * Updates the topology bulk backoff ceiling. Invoked by the cluster-settings update consumer
     * registered for {@link #BULK_TOPOLOGY_MAX_BACKOFF_MILLIS}.
     *
     * @param bulkTopologyMaxBackoffMillis the new maximum backoff in milliseconds.
     */
    public void setBulkTopologyMaxBackoffMillis(long bulkTopologyMaxBackoffMillis) {
        this.bulkTopologyMaxBackoffMillis = bulkTopologyMaxBackoffMillis;
    }

    /**
     * Retrieves the maximum number of job-scheduler registration attempts.
     *
     * @return the maximum number of retries.
     */
    public int getJobScheduleMaxRetries() {
        return this.jobScheduleMaxRetries;
    }

    /**
     * Retrieves the base delay, in seconds, for the linear backoff between job-registration attempts.
     *
     * @return the base backoff delay in seconds.
     */
    public int getJobScheduleRetryBackoffSeconds() {
        return this.jobScheduleRetryBackoffSeconds;
    }

    /**
     * Retrieves the maximum number of resource-creation lock acquisition attempts.
     *
     * @return the maximum number of retries.
     */
    public int getResourceLockMaxRetries() {
        return this.resourceLockMaxRetries;
    }

    /**
     * Updates the resource-lock retry budget. Invoked by the cluster-settings update consumer
     * registered for {@link #RESOURCE_LOCK_MAX_RETRIES}.
     *
     * @param resourceLockMaxRetries the new maximum number of retries.
     */
    public void setResourceLockMaxRetries(int resourceLockMaxRetries) {
        this.resourceLockMaxRetries = resourceLockMaxRetries;
    }

    /**
     * Retrieves the delay, in milliseconds, between resource-creation lock acquisition attempts.
     *
     * @return the backoff delay in milliseconds.
     */
    public long getResourceLockRetryBackoffMillis() {
        return this.resourceLockRetryBackoffMillis;
    }

    /**
     * Updates the resource-lock retry backoff. Invoked by the cluster-settings update consumer
     * registered for {@link #RESOURCE_LOCK_RETRY_BACKOFF_MILLIS}.
     *
     * @param resourceLockRetryBackoffMillis the new backoff delay in milliseconds.
     */
    public void setResourceLockRetryBackoffMillis(long resourceLockRetryBackoffMillis) {
        this.resourceLockRetryBackoffMillis = resourceLockRetryBackoffMillis;
    }

    /**
     * Retrieves the age, in milliseconds, past which a held resource-creation lock is treated as
     * stale.
     *
     * @return the stale threshold in milliseconds.
     */
    public long getResourceLockStaleThresholdMillis() {
        return this.resourceLockStaleThresholdMillis;
    }

    /**
     * Updates the resource-lock stale threshold. Invoked by the cluster-settings update consumer
     * registered for {@link #RESOURCE_LOCK_STALE_THRESHOLD_MILLIS}.
     *
     * @param resourceLockStaleThresholdMillis the new stale threshold in milliseconds.
     */
    public void setResourceLockStaleThresholdMillis(long resourceLockStaleThresholdMillis) {
        this.resourceLockStaleThresholdMillis = resourceLockStaleThresholdMillis;
    }

    /**
     * Retrieves the maximum number of attempts to write the user-overrides registry document.
     *
     * @return the maximum number of attempts.
     */
    public int getUserOverridesMaxUpdateAttempts() {
        return this.userOverridesMaxUpdateAttempts;
    }

    /**
     * Updates the user-overrides write budget. Invoked by the cluster-settings update consumer
     * registered for {@link #USER_OVERRIDES_MAX_UPDATE_ATTEMPTS}.
     *
     * @param userOverridesMaxUpdateAttempts the new maximum number of attempts.
     */
    public void setUserOverridesMaxUpdateAttempts(int userOverridesMaxUpdateAttempts) {
        this.userOverridesMaxUpdateAttempts = userOverridesMaxUpdateAttempts;
    }

    /**
     * Retrieves the maximum number of attempts to update an integration document on a version
     * conflict.
     *
     * @return the maximum number of attempts.
     */
    public int getIntegrationMaxUpdateAttempts() {
        return this.integrationMaxUpdateAttempts;
    }

    /**
     * Updates the integration write budget. Invoked by the cluster-settings update consumer
     * registered for {@link #INTEGRATION_MAX_UPDATE_ATTEMPTS}.
     *
     * @param integrationMaxUpdateAttempts the new maximum number of attempts.
     */
    public void setIntegrationMaxUpdateAttempts(int integrationMaxUpdateAttempts) {
        this.integrationMaxUpdateAttempts = integrationMaxUpdateAttempts;
    }

    /**
     * Retrieves the request timeout, in seconds, for CTI Console calls.
     *
     * @return the timeout in seconds.
     */
    public int getCtiRequestTimeout() {
        return this.ctiRequestTimeout;
    }

    /**
     * Retrieves the upper bound, in minutes, on a single Engine content reload.
     *
     * @return the reload timeout in minutes.
     */
    public int getEngineReloadTimeoutMinutes() {
        return this.engineReloadTimeoutMinutes;
    }

    /**
     * Retrieves the grace period, in minutes, before a content-not-ready deferral is escalated to a
     * warning.
     *
     * @return the grace period in minutes.
     */
    public int getEngineNotReadyGraceMinutes() {
        return this.engineNotReadyGraceMinutes;
    }

    /**
     * Retrieves the filesystem path of the Engine API Unix domain socket.
     *
     * @return the socket path.
     */
    public String getEngineSocketPath() {
        return this.engineSocketPath;
    }

    /**
     * Retrieves the timeout, in seconds, for a Security Analytics bulk synchronization step.
     *
     * @return the timeout in seconds.
     */
    public int getSaSyncTimeoutSeconds() {
        return this.saSyncTimeoutSeconds;
    }

    /**
     * Retrieves the timeout, in seconds, for the first detector creation.
     *
     * @return the timeout in seconds.
     */
    public int getSaDetectorTimeoutSeconds() {
        return this.saDetectorTimeoutSeconds;
    }

    /**
     * Retrieves the timeout, in seconds, for deleting stale Security Analytics resources.
     *
     * @return the timeout in seconds.
     */
    public int getSaCleanupTimeoutSeconds() {
        return this.saCleanupTimeoutSeconds;
    }

    /**
     * Retrieves the detector schedule interval, in minutes, used when the CTI document does not carry
     * a usable one.
     *
     * @return the detector interval in minutes.
     */
    public int getSaDetectorInterval() {
        return this.saDetectorInterval;
    }

    /**
     * Updates the default detector interval. Invoked by the cluster-settings update consumer
     * registered for {@link #SA_DETECTOR_INTERVAL}.
     *
     * @param saDetectorInterval the new detector interval in minutes.
     */
    public void setSaDetectorInterval(int saDetectorInterval) {
        this.saDetectorInterval = saDetectorInterval;
    }

    /**
     * Retrieves the maximum number of UPDATE offsets batched into a single MultiGet + BulkRequest.
     *
     * @return the sub-batch size.
     */
    public int getUpdateSubBatchSize() {
        return this.updateSubBatchSize;
    }

    /**
     * Retrieves how many batches or bulks are processed between consumer-offset checkpoints.
     *
     * @return the flush interval.
     */
    public int getOffsetFlushInterval() {
        return this.offsetFlushInterval;
    }

    /**
     * Retrieves the page size used by the internal paginated content searches.
     *
     * @return the search page size.
     */
    public int getSearchPageSize() {
        return this.searchPageSize;
    }

    @Override
    public String toString() {
        return "{"
                + "ctiBaseUrl='"
                + this.ctiBaseUrl
                + "', "
                + "maximumItemsPerBulk="
                + this.maximumItemsPerBulk
                + ", "
                + "maximumBulkBytes="
                + this.maximumBulkBytes
                + ", "
                + "maximumConcurrentBulks="
                + this.maximumConcurrentBulks
                + ", "
                + "clientTimeout="
                + this.clientTimeout
                + ", "
                + "catalogSyncInterval="
                + this.catalogSyncInterval
                + ", "
                + "updateOnStart="
                + this.updateOnStart
                + ", "
                + "updateOnSchedule="
                + this.updateOnSchedule
                + ", "
                + "catalogRuleset='"
                + this.catalogRuleset
                + "', "
                + "catalogIocs='"
                + this.catalogIocs
                + "', "
                + "catalogVulnerabilities='"
                + this.catalogVulnerabilities
                + "', "
                + "setupWaitMaxRetries="
                + this.setupWaitMaxRetries
                + ", "
                + "setupWaitBackoffBaseSeconds="
                + this.setupWaitBackoffBaseSeconds
                + "}";
    }
}
