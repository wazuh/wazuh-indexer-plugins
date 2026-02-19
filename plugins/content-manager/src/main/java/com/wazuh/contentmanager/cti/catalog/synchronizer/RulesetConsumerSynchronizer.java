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
package com.wazuh.contentmanager.cti.catalog.synchronizer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
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
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;
import com.wazuh.securityanalytics.action.*;

/**
 * Handles synchronization logic for the unified content consumer. Processes rules, decoders, kvdbs,
 * integrations, and policies. It also handles post-sync operations like creating detectors and
 * calculating policy hashes.
 */
public class RulesetConsumerSynchronizer extends AbstractConsumerSynchronizer {

    private static final Logger log = LogManager.getLogger(RulesetConsumerSynchronizer.class);
    private final ObjectMapper mapper;

    private final String CONTEXT = PluginSettings.getInstance().getContentContext();
    private final String CONSUMER = PluginSettings.getInstance().getContentConsumer();

    private final SecurityAnalyticsServiceImpl securityAnalyticsService;
    private final PolicyHashService policyHashService;

    /**
     * Constructs a new UnifiedConsumerSynchronizer.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     */
    public RulesetConsumerSynchronizer(
            Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
        this.securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        this.policyHashService = new PolicyHashService(client);

        this.mapper = new ObjectMapper();
        this.mapper.setSerializationInclusion(JsonInclude.Include.ALWAYS);
        this.mapper
                .configOverride(Policy.class)
                .setInclude(
                        JsonInclude.Value.construct(JsonInclude.Include.ALWAYS, JsonInclude.Include.ALWAYS));
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
        if (isUpdated) {
            this.refreshIndices(
                    Constants.INDEX_RULES,
                    Constants.INDEX_DECODERS,
                    Constants.INDEX_KVDBS,
                    Constants.INDEX_INTEGRATIONS,
                    Constants.INDEX_FILTERS,
                    Constants.INDEX_POLICIES);

            // Initialize default spaces if they don't exist
            this.initializeSpaces();

            // Sync Integrations
            this.syncIntegrations();

            // Sync Rules
            this.syncRules();

            // Sync Detectors
            if (PluginSettings.getInstance().getCreateDetectors()) {
                this.syncDetectors();
            }

            this.policyHashService.calculateAndUpdate();
        }
    }

    /**
     * Synchronizes Integrations from the internal index to the Security Analytics Plugin. Uses
     * parallel execution with a CountDownLatch to ensure all async requests complete.
     */
    private void syncIntegrations() {
        if (!this.indexExists(Constants.INDEX_INTEGRATIONS)) {
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
            WIndexIntegrationRequest request =
                    this.securityAnalyticsService.buildIntegrationRequest(
                            doc, space, RestRequest.Method.POST);

            if (request == null) {
                latch.countDown();
                continue;
            }

            this.client.execute(
                    WIndexIntegrationAction.INSTANCE,
                    request,
                    new ActionListener<WIndexIntegrationResponse>() {
                        @Override
                        public void onResponse(WIndexIntegrationResponse response) {
                            latch.countDown();
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to sync integration {}: {}", hit.getId(), e.getMessage());
                            latch.countDown();
                        }
                    });
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
        if (!this.indexExists(Constants.INDEX_RULES)) {
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
            if (!doc.has(Constants.KEY_ID)) {
                latch.countDown();
                continue;
            }

            String id = doc.get(Constants.KEY_ID).asText();
            String product = ContentIndex.extractProduct(doc);
            String body = doc.toString();

            if (space != Space.STANDARD) {
                WIndexCustomRuleRequest request =
                        new WIndexCustomRuleRequest(
                                id,
                                WriteRequest.RefreshPolicy.IMMEDIATE,
                                product,
                                RestRequest.Method.POST,
                                body,
                                true);

                this.client.execute(
                        WIndexCustomRuleAction.INSTANCE,
                        request,
                        new ActionListener<WIndexRuleResponse>() {
                            @Override
                            public void onResponse(WIndexRuleResponse response) {
                                latch.countDown();
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error("Failed to sync rule {}: {}", hit.getId(), e.getMessage());
                                latch.countDown();
                            }
                        });
            } else {
                WIndexRuleRequest request =
                        new WIndexRuleRequest(
                                id,
                                WriteRequest.RefreshPolicy.IMMEDIATE,
                                product,
                                RestRequest.Method.POST,
                                body,
                                true);

                this.client.execute(
                        WIndexRuleAction.INSTANCE,
                        request,
                        new ActionListener<WIndexRuleResponse>() {
                            @Override
                            public void onResponse(WIndexRuleResponse response) {
                                latch.countDown();
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error("Failed to sync rule {}: {}", hit.getId(), e.getMessage());
                                latch.countDown();
                            }
                        });
            }
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
     * Synchronizes Threat Detectors to the Security Analytics Plugin. Detectors are created only for
     * Standard integrations and are processed sequentially.
     */
    private void syncDetectors() {
        if (!this.indexExists(Constants.INDEX_INTEGRATIONS)) {
            return;
        }

        SearchResponse searchResponse = this.searchAll(Constants.INDEX_INTEGRATIONS);
        SearchHit[] hits = searchResponse.getHits().getHits();

        List<SearchHit> hitsToProcess = new ArrayList<>();
        for (SearchHit hit : hits) {
            JsonNode source = this.parseHit(hit);
            if (source != null && this.extractSpace(source) == Space.STANDARD) {
                hitsToProcess.add(hit);
            }
        }

        if (hitsToProcess.isEmpty()) return;

        CountDownLatch latch = new CountDownLatch(1);
        this.processNextDetector(hitsToProcess.iterator(), latch);

        try {
            if (!latch.await(60, TimeUnit.SECONDS)) {
                log.warn("Timed out waiting for detectors sync");
            }
        } catch (InterruptedException e) {
            log.error("Interrupted waiting for detectors sync", e);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Recursively processes the next detector in the list. Sequential processing is used to avoid
     * race conditions during detector configuration index creation in SAP.
     *
     * @param iterator Iterator for the list of search hits to process.
     * @param latch Latch used to signal completion of the entire list.
     */
    private void processNextDetector(Iterator<SearchHit> iterator, CountDownLatch latch) {
        if (!iterator.hasNext()) {
            latch.countDown();
            return;
        }

        SearchHit hit = iterator.next();
        JsonNode source = this.parseHit(hit);
        JsonNode doc = source != null ? this.extractDocument(source, hit.getId()) : null;

        if (doc == null) {
            this.processNextDetector(iterator, latch);
            return;
        }

        WIndexDetectorRequest request = this.securityAnalyticsService.buildDetectorRequest(doc, true);
        if (request == null) {
            this.processNextDetector(iterator, latch);
            return;
        }

        this.client.execute(
                WIndexDetectorAction.INSTANCE,
                request,
                new ActionListener<WIndexDetectorResponse>() {
                    @Override
                    public void onResponse(WIndexDetectorResponse response) {
                        RulesetConsumerSynchronizer.this.processNextDetector(iterator, latch);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to sync detector {}: {}", hit.getId(), e.getMessage());
                        RulesetConsumerSynchronizer.this.processNextDetector(iterator, latch);
                    }
                });
    }

    /**
     * Creates default policy documents for user spaces (draft, testing, custom) if they don't exist.
     */
    private void initializeSpaces() {
        // Generate a deterministic ID shared across all default policies so they are linked.
        // Using a name-based UUID (v3) ensures all nodes produce the same ID for the same seed.
        String sharedDocumentId =
                UUID.nameUUIDFromBytes("wazuh-default-policy".getBytes(StandardCharsets.UTF_8)).toString();
        this.initializeSpace(Space.DRAFT.toString(), sharedDocumentId);
        this.initializeSpace(Space.TEST.toString(), sharedDocumentId);
        this.initializeSpace(Space.CUSTOM.toString(), sharedDocumentId);
    }

    /**
     * Creates a single space policy document if it does not already exist.
     *
     * @param spaceName The space name.
     */
    private void initializeSpace(String spaceName, String documentId) {
        try {
            SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName));
            searchSourceBuilder.size(0);

            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();

            // Proceed only if no document with this space name exists
            if (Objects.requireNonNull(searchResponse.getHits().getTotalHits()).value() == 0) {
                ContentUtils contentUtils = new ContentUtils();
                String date = contentUtils.getCurrentDate();
                String title = "Custom policy";

                Policy policy = new Policy();
                policy.setId(documentId);
                policy.setTitle(title);
                policy.setDescription(title);
                policy.setAuthor("Wazuh Inc.");
                policy.setRootDecoder("");
                policy.setDocumentation("");
                policy.setIntegrations(Collections.emptyList());
                policy.setFilters(Collections.emptyList());
                policy.setEnrichments(Collections.emptyList());
                policy.setReferences(List.of("https://wazuh.com"));
                policy.setDate(date);
                policy.setModified(date);

                // TODO: Study the model policy and delete the extra fields
                Map<String, Object> docMap = this.mapper.convertValue(policy, Map.class);
                docMap.remove(Constants.KEY_TYPE); // Delete the field type inside the document

                String docJson = this.mapper.writeValueAsString(docMap);
                String docHash = HashCalculator.sha256(docJson);

                Map<String, Object> space = new HashMap<>();
                space.put(Constants.KEY_NAME, spaceName);
                space.put(Constants.KEY_HASH, Map.of(Constants.KEY_SHA256, docHash));

                Map<String, Object> source = new HashMap<>();
                source.put(Constants.KEY_DOCUMENT, docMap);
                source.put(Constants.KEY_SPACE, space);
                // TODO: change to usage of method to calculate space hash
                source.put(Constants.KEY_HASH, Map.of(Constants.KEY_SHA256, docHash));

                IndexRequest request =
                        new IndexRequest(Constants.INDEX_POLICIES)
                                .source(this.mapper.writeValueAsString(source), XContentType.JSON)
                                .opType(DocWriteRequest.OpType.CREATE)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                this.client.index(request).actionGet();
            }
        } catch (Exception e) {
            log.error("Failed to initialize space [{}]: {}", spaceName, e.getMessage());
        }
    }

    /**
     * Checks if the specified index exists in the cluster.
     *
     * @param indexName The name of the index to check.
     * @return true if the index exists, false otherwise.
     */
    private boolean indexExists(String indexName) {
        return this.client.admin().indices().prepareExists(indexName).get().isExists();
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
