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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.env.Environment;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Handles synchronization logic for the unified content consumer. Processes rules, decoders, kvdbs,
 * integrations, and policies. It also handles post-sync operations like creating detectors and
 * calculating policy hashes.
 */
public class ConsumerRulesetService extends AbstractConsumerService {

    private static final Logger log = LogManager.getLogger(ConsumerRulesetService.class);
    private final ObjectMapper mapper;

    private final String CONTEXT = PluginSettings.getInstance().getContentContext();
    private final String CONSUMER = PluginSettings.getInstance().getContentConsumer();

    private SecurityAnalyticsServiceImpl securityAnalyticsService;
    private SpaceService spaceService;
    private final EngineService engineService;

    /**
     * Constructs a new UnifiedConsumerSynchronizer.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     * @param engineService The engine service for loading content into the Engine.
     */
    public ConsumerRulesetService(
            Client client,
            ConsumersIndex consumersIndex,
            Environment environment,
            EngineService engineService) {
        super(client, consumersIndex, environment);
        this.securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        this.spaceService = new SpaceService(client);
        this.engineService = engineService;

        this.mapper = new ObjectMapper();
        this.mapper.setSerializationInclusion(JsonInclude.Include.ALWAYS);
        this.mapper
                .configOverride(Policy.class)
                .setInclude(
                        JsonInclude.Value.construct(JsonInclude.Include.ALWAYS, JsonInclude.Include.ALWAYS));
    }

    /**
     * Runs the Standard space cleanup (if needed) before delegating to the parent synchronization
     * logic. This ensures that stale resources from a previous consumer are removed before the new
     * consumer's snapshot is loaded.
     */
    @Override
    public void synchronize() {
        this.cleanupStandardSpaceIfConsumerChanged();
        super.synchronize();
    }

    /**
     * Detects whether the content consumer/context settings have changed since the last sync and, if
     * so, cleans up the Standard space before the new consumer's snapshot is loaded.
     *
     * <p>Detection heuristic: if no {@link com.wazuh.contentmanager.cti.catalog.model.LocalConsumer}
     * document exists for the current composite ID ({@code context_consumer}) AND the Standard space
     * already contains resources, then a consumer switch has occurred and cleanup is required.
     */
    void cleanupStandardSpaceIfConsumerChanged() {
        try {
            // 1. Check if a LocalConsumer document exists for the current context/consumer
            GetResponse consumerDoc = this.consumersIndex.getConsumer(this.CONTEXT, this.CONSUMER);

            if (consumerDoc != null && consumerDoc.isExists()) {
                // Consumer doc already exists -- no setting change detected.
                return;
            }

            // 2. No consumer doc for the current ID. Check if Standard space has resources.
            Map<String, Map<String, String>> spaceResources =
                    this.spaceService.getSpaceResources(Space.STANDARD.toString());

            boolean hasResources =
                    spaceResources.values().stream().anyMatch(m -> m != null && !m.isEmpty());

            if (!hasResources) {
                log.info("No existing Standard space resources found. Skipping cleanup.");
                return;
            }

            // 3. Consumer changed and old resources exist. Clean up.
            log.info("Consumer setting change detected. Cleaning up Standard space before re-sync.");
            this.spaceService.resetSpace(Space.STANDARD, this.securityAnalyticsService);
            log.info("Standard space cleanup completed successfully.");

        } catch (Exception e) {
            log.error("Failed to perform Standard space cleanup on consumer change: {}", e.getMessage());
        }
    }

    /**
     * Setter for spaceService to allow injection in tests.
     *
     * @param spaceService the space service to set
     */
    void setSpaceService(SpaceService spaceService) {
        this.spaceService = spaceService;
    }

    /**
     * Setter for securityAnalyticsService to allow injection in tests.
     *
     * @param securityAnalyticsService the security analytics service to set
     */
    void setSecurityAnalyticsService(SecurityAnalyticsServiceImpl securityAnalyticsService) {
        this.securityAnalyticsService = securityAnalyticsService;
    }

    /**
     * Retrieves the context name for this synchronizer.
     *
     * @return The context string.
     */
    @Override
    protected String getContext() {
        return this.CONTEXT;
    }

    /**
     * Retrieves the consumer name for this synchronizer.
     *
     * @return The consumer string.
     */
    @Override
    protected String getConsumer() {
        return this.CONSUMER;
    }

    @Override
    protected String getSnapshotFilename() {
        return Constants.CONTENT_SNAPSHOT_FILENAME;
    }

    /**
     * Returns the Standard space name so that snapshot loading only clears STANDARD documents,
     * preserving DRAFT, TEST, and CUSTOM resources in shared indices.
     *
     * @return The standard space name.
     */
    @Override
    protected String getSnapshotClearSpace() {
        return Space.STANDARD.toString();
    }

    /**
     * Returns the mappings configuration for the indices handled by this synchronizer.
     *
     * @return A map where keys are resource types and values are mapping file paths.
     */
    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(Constants.KEY_RULE, "/mappings/cti-rules-mappings.json");
        mappings.put(Constants.KEY_DECODER, "/mappings/cti-decoders-mappings.json");
        mappings.put(Constants.KEY_KVDB, "/mappings/cti-kvdbs-mappings.json");
        mappings.put(Constants.KEY_INTEGRATION, "/mappings/cti-integrations-mappings.json");
        mappings.put(Constants.KEY_FILTERS, "/mappings/engine-filters-mappings.json");
        mappings.put(Constants.KEY_POLICY, "/mappings/cti-policies-mappings.json");
        return mappings;
    }

    /**
     * Returns the aliases configuration for the indices.
     *
     * @return An empty map as indices are accessed by their names directly.
     */
    @Override
    protected Map<String, String> getAliases() {
        // We use the alias names as the actual index names, so we do not create separate aliases.
        return Collections.emptyMap();
    }

    /**
     * Triggered when the primary synchronization is finished. Refreshes indices, initializes spaces,
     * and synchronizes SAP resources.
     *
     * @param isUpdated Indicates if the content was updated during sync.
     */
    @Override
    public void onSyncComplete(boolean isUpdated) {
        this.initializeSpaces();

        if (isUpdated) {
            this.refreshIndices(
                    Constants.INDEX_RULES,
                    Constants.INDEX_DECODERS,
                    Constants.INDEX_KVDBS,
                    Constants.INDEX_INTEGRATIONS,
                    Constants.INDEX_FILTERS,
                    Constants.INDEX_POLICIES);

            // Sync Integrations
            try {
                this.syncIntegrations();
            } catch (Exception e) {
                log.error(Constants.E_LOG_SAP_SYNC_FAILED, "integrations", e.getMessage(), e);
            }

            // Sync Rules
            try {
                this.syncRules();
            } catch (Exception e) {
                log.error(Constants.E_LOG_SAP_SYNC_FAILED, "rules", e.getMessage(), e);
            }

            // Sync Detectors
            if (PluginSettings.getInstance().getCreateDetectors()) {
                try {
                    this.syncDetectors();
                } catch (Exception e) {
                    log.error(Constants.E_LOG_SAP_SYNC_FAILED, "detectors", e.getMessage(), e);
                }
            }

            Set<String> changedSpaces = this.spaceService.calculateAndUpdate();

            // Load the standard space into the Engine only if its hash changed
            if (changedSpaces.contains(Space.STANDARD.toString())) {
                this.loadStandardSpaceIntoEngine();
            }
        }
    }

    /** Builds the engine payload for the standard space and loads it into the Engine. */
    private void loadStandardSpaceIntoEngine() {
        if (this.engineService == null) {
            log.warn(Constants.E_LOG_ENGINE_IS_NULL);
            return;
        }
        try {
            JsonNode payload = this.spaceService.buildEnginePayload(Space.STANDARD.toString());
            RestResponse response = this.engineService.promote(payload);
            if (response.getStatus() == RestStatus.OK.getStatus()) {
                log.info("Engine load for standard space completed successfully.");
            } else {
                log.warn(
                        "Engine load for standard space returned status [{}]: {}",
                        response.getStatus(),
                        response.getMessage());
            }
        } catch (Exception e) {
            log.error("Failed to load standard space into Engine: {}", e.getMessage());
        }
    }

    /**
     * Synchronizes Integrations from the internal index to the Security Analytics Plugin. Uses
     * parallel execution with a CountDownLatch to ensure all async requests complete.
     */
    private void syncIntegrations() {
        if (this.indexIsMissing(Constants.INDEX_INTEGRATIONS)) {
            return;
        }

        SearchResponse searchResponse = this.searchAll(Constants.INDEX_INTEGRATIONS);
        SearchHit[] hits = searchResponse.getHits().getHits();
        if (hits.length == 0) return;

        CountDownLatch latch = new CountDownLatch(hits.length);

        for (SearchHit hit : hits) {
            JsonNode source = this.parseHit(hit);
            if (source == null) {
                latch.countDown();
                continue;
            }
            JsonNode doc = this.extractDocument(source, hit.getId());
            if (doc == null) {
                latch.countDown();
                continue;
            }
            Space space = this.extractSpace(source);

            this.securityAnalyticsService.upsertIntegrationAsync(
                    doc,
                    space,
                    RestRequest.Method.POST,
                    ActionListener.wrap(
                            response -> latch.countDown(),
                            e -> {
                                log.error("Failed to sync integration {}: {}", hit.getId(), e.getMessage());
                                latch.countDown();
                            }));
        }

        try {
            if (!latch.await(60, TimeUnit.SECONDS)) {
                log.warn("Timed out waiting for integrations sync");
            }
        } catch (InterruptedException e) {
            log.error("Interrupted waiting for integrations sync", e);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Synchronizes Rules from the internal index to the Security Analytics Plugin. Supports both
     * Standard and Custom rules.
     */
    private void syncRules() {
        if (this.indexIsMissing(Constants.INDEX_RULES)) {
            return;
        }

        SearchResponse searchResponse = this.searchAll(Constants.INDEX_RULES);
        SearchHit[] hits = searchResponse.getHits().getHits();
        if (hits.length == 0) return;

        CountDownLatch latch = new CountDownLatch(hits.length);

        for (SearchHit hit : hits) {
            JsonNode source = this.parseHit(hit);
            if (source == null) {
                latch.countDown();
                continue;
            }
            JsonNode doc = this.extractDocument(source, hit.getId());
            if (doc == null) {
                latch.countDown();
                continue;
            }
            Space space = this.extractSpace(source);

            this.securityAnalyticsService.upsertRuleAsync(
                    doc,
                    space,
                    RestRequest.Method.POST,
                    ActionListener.wrap(
                            response -> latch.countDown(),
                            e -> {
                                log.error("Failed to sync rule {}: {}", hit.getId(), e.getMessage());
                                latch.countDown();
                            }));
        }

        try {
            if (!latch.await(60, TimeUnit.SECONDS)) {
                log.warn("Timed out waiting for rules sync");
            }
        } catch (InterruptedException e) {
            log.error("Interrupted waiting for rules sync", e);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Synchronizes Threat Detectors to the Security Analytics Plugin. The first detector is created
     * sequentially to ensure the SAP detectors config index exists, then the remaining detectors are
     * created in parallel.
     */
    private void syncDetectors() {
        if (this.indexIsMissing(Constants.INDEX_INTEGRATIONS)) {
            return;
        }

        SearchResponse searchResponse = this.searchAll(Constants.INDEX_INTEGRATIONS);
        SearchHit[] hits = searchResponse.getHits().getHits();

        // Pre-filter: only keep standard-space integrations with a valid detector request
        List<JsonNode> docs = new ArrayList<>();
        for (SearchHit hit : hits) {
            JsonNode source = this.parseHit(hit);
            if (source == null || this.extractSpace(source) != Space.STANDARD) {
                continue;
            }
            JsonNode doc = this.extractDocument(source, hit.getId());
            if (doc != null && this.securityAnalyticsService.buildDetectorRequest(doc, true) != null) {
                docs.add(doc);
            }
        }

        if (docs.isEmpty()) return;

        log.info(
                "Syncing {} detectors ({} sequentially, {} in parallel)", docs.size(), 1, docs.size() - 1);

        // Process the first detector sequentially to ensure the config index is created
        CountDownLatch firstLatch = new CountDownLatch(1);
        JsonNode firstDoc = docs.getFirst();
        String firstName =
                firstDoc.has("metadata") && firstDoc.get("metadata").has("title")
                        ? firstDoc.get("metadata").get("title").asText()
                        : "unknown";
        this.securityAnalyticsService.upsertDetectorAsync(
                firstDoc,
                true,
                RestRequest.Method.POST,
                ActionListener.wrap(
                        response -> firstLatch.countDown(),
                        e -> {
                            log.error(
                                    "Failed to sync detector for integration [{}]: {}", firstName, e.getMessage());
                            firstLatch.countDown();
                        }));

        try {
            if (!firstLatch.await(30, TimeUnit.SECONDS)) {
                log.warn("Timed out waiting for first detector creation");
                return;
            }
        } catch (InterruptedException e) {
            log.error("Interrupted waiting for first detector", e);
            Thread.currentThread().interrupt();
            return;
        }

        // Process remaining detectors in parallel
        if (docs.size() > 1) {
            CountDownLatch parallelLatch = new CountDownLatch(docs.size() - 1);
            for (int i = 1; i < docs.size(); i++) {
                JsonNode doc = docs.get(i);
                String name =
                        doc.has("metadata") && doc.get("metadata").has("title")
                                ? doc.get("metadata").get("title").asText()
                                : "unknown";
                this.securityAnalyticsService.upsertDetectorAsync(
                        doc,
                        true,
                        RestRequest.Method.POST,
                        ActionListener.wrap(
                                response -> parallelLatch.countDown(),
                                e -> {
                                    log.error(
                                            "Failed to sync detector for integration [{}]: {}", name, e.getMessage());
                                    parallelLatch.countDown();
                                }));
            }

            try {
                if (!parallelLatch.await(60, TimeUnit.SECONDS)) {
                    log.warn("Timed out waiting for parallel detectors sync");
                }
            } catch (InterruptedException e) {
                log.error("Interrupted waiting for detectors sync", e);
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Creates default policy documents for user spaces (draft, testing, custom) if they don't exist.
     */
    private void initializeSpaces() {
        // Generate a deterministic ID shared across all default policies so they are linked.
        // Using a name-based UUID (v3) ensures all nodes produce the same ID for the same seed.
        String sharedDocumentId =
                UUID.nameUUIDFromBytes("wazuh-default-policy".getBytes(StandardCharsets.UTF_8)).toString();
        this.spaceService.initializeSpace(Space.DRAFT.toString(), sharedDocumentId);
        this.spaceService.initializeSpace(Space.TEST.toString(), sharedDocumentId);
        this.spaceService.initializeSpace(Space.CUSTOM.toString(), sharedDocumentId);
    }

    /**
     * Checks if the specified index exists in the cluster.
     *
     * @param indexName The name of the index to check.
     * @return true if the index exists, false otherwise.
     */
    private boolean indexIsMissing(String indexName) {
        return !this.client.admin().indices().prepareExists(indexName).get().isExists();
    }

    /**
     * Executes a match-all search query on the specified index to retrieve all documents.
     *
     * <p>The search size is set to 10,000 to retrieve a large batch of documents.
     *
     * @param indexName The name of the index to search.
     * @return The {@link SearchResponse} containing the search hits.
     */
    private SearchResponse searchAll(String indexName) {
        SearchRequest searchRequest = new SearchRequest(indexName);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.matchAllQuery());
        searchSourceBuilder.size(10000);
        searchRequest.source(searchSourceBuilder);
        return this.client.search(searchRequest).actionGet();
    }

    /**
     * Parses a {@link SearchHit} source string into a {@link JsonNode}.
     *
     * @param hit The search hit to parse.
     * @return The parsed {@link JsonNode}, or null if a syntax error occurs during parsing.
     */
    private JsonNode parseHit(SearchHit hit) {
        try {
            return this.mapper.readTree(hit.getSourceAsString());
        } catch (Exception e) {
            log.error("Failed to parse JSON from hit [{}]: {}", hit.getId(), e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the inner "document" object from the source wrapper.
     *
     * @param source The source JSON object (the wrapper containing metadata and the document).
     * @param hitId The ID of the hit, used for logging if the document field is missing.
     * @return The inner "document" {@link JsonNode}, or null if the key is missing.
     */
    private JsonNode extractDocument(JsonNode source, String hitId) {
        if (!source.has(Constants.KEY_DOCUMENT)) {
            log.warn("Hit [{}] missing 'document' field, skipping", hitId);
            return null;
        }
        return source.get(Constants.KEY_DOCUMENT);
    }

    /**
     * Extracts the {@link Space} from the source JSON object.
     *
     * <p>It looks for the "space.name" field. If the field is missing or the value is invalid, it
     * defaults to {@link Space#STANDARD}.
     *
     * @param source The source JSON object.
     * @return The extracted {@link Space}, or {@link Space#STANDARD} if not found or invalid.
     */
    private Space extractSpace(JsonNode source) {
        if (source.has(Constants.KEY_SPACE) && source.get(Constants.KEY_SPACE).isObject()) {
            JsonNode space = source.get(Constants.KEY_SPACE);
            if (space.has(Constants.KEY_NAME)) {
                try {
                    return Space.fromValue(space.get(Constants.KEY_NAME).asText());
                } catch (IllegalArgumentException e) {
                    return Space.STANDARD;
                }
            }
        }
        return Space.STANDARD;
    }
}
