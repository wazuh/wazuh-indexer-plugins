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
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.Environment;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.time.LocalDate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.processor.DetectorProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.IntegrationProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.RuleProcessor;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Handles synchronization logic for the unified content consumer. Processes rules, decoders, kvdbs,
 * integrations, and policies. It also handles post-sync operations like creating detectors and
 * calculating policy hashes.
 */
public class UnifiedConsumerSynchronizer extends AbstractConsumerSynchronizer {

    private static final Logger log = LogManager.getLogger(UnifiedConsumerSynchronizer.class);
    private final ObjectMapper mapper;

    public static final String POLICY = "policy";
    public static final String RULE = "rule";
    public static final String DECODER = "decoder";
    public static final String KVDB = "kvdb";
    public static final String INTEGRATION = "integration";

    /** The unified context identifier. */
    private final String CONTEXT = PluginSettings.getInstance().getContentContext();

    /** The unified consumer name identifier. */
    private final String CONSUMER = PluginSettings.getInstance().getContentConsumer();

    private final IntegrationProcessor integrationProcessor;
    private final RuleProcessor ruleProcessor;
    private final DetectorProcessor detectorProcessor;
    private final PolicyHashService policyHashService;

    /**
     * Constructs a new UnifiedConsumerSynchronizer.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     */
    public UnifiedConsumerSynchronizer(
            Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
        this.integrationProcessor = new IntegrationProcessor(client);
        this.ruleProcessor = new RuleProcessor(client);
        this.detectorProcessor = new DetectorProcessor(client);
        this.policyHashService = new PolicyHashService(client);

        this.mapper = new ObjectMapper();
        this.mapper.setSerializationInclusion(JsonInclude.Include.ALWAYS);
        this.mapper
                .configOverride(Policy.class)
                .setInclude(
                        JsonInclude.Value.construct(JsonInclude.Include.ALWAYS, JsonInclude.Include.ALWAYS));
    }

    @Override
    protected String getContext() {
        return this.CONTEXT;
    }

    @Override
    protected String getConsumer() {
        return this.CONSUMER;
    }

    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(RULE, "/mappings/cti-rules-mappings.json");
        mappings.put(DECODER, "/mappings/cti-decoders-mappings.json");
        mappings.put(KVDB, "/mappings/cti-kvdbs-mappings.json");
        mappings.put(INTEGRATION, "/mappings/cti-integrations-mappings.json");
        mappings.put(POLICY, "/mappings/cti-policies-mappings.json");
        return mappings;
    }

    @Override
    protected Map<String, String> getAliases() {
        // We use the alias names as the actual index names, so we do not create separate aliases.
        return Collections.emptyMap();
    }

    /**
     * Overrides index naming to utilize the alias name convention directly.
     *
     * @param type The type identifier for the index.
     * @return The unified index name.
     */
    @Override
    public String getIndexName(String type) {
        switch (type) {
            case RULE:
                return ".cti-rules";
            case DECODER:
                return ".cti-decoders";
            case KVDB:
                return ".cti-kvdbs";
            case INTEGRATION:
                return ".cti-integrations";
            case POLICY:
                return ".cti-policies";
            default:
                return super.getIndexName(type);
        }
    }

    @Override
    protected void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            this.refreshIndices(RULE, DECODER, KVDB, INTEGRATION, POLICY);

            String integrationIndex = this.getIndexName(INTEGRATION);
            String ruleIndex = this.getIndexName(RULE);
            String policyIndex = this.getIndexName(POLICY);
            String decoderIndex = this.getIndexName(DECODER);
            String kvdbIndex = this.getIndexName(KVDB);

            // Initialize default spaces if they don't exist
            this.initializeSpaces(policyIndex);

            Map<String, List<String>> integrations = this.integrationProcessor.process(integrationIndex);
            this.ruleProcessor.process(ruleIndex);
            this.detectorProcessor.process(integrations, integrationIndex);

            this.policyHashService.calculateAndUpdate(
                    policyIndex, integrationIndex, decoderIndex, kvdbIndex, ruleIndex);
        }
    }

    /**
     * Creates default policy documents for user spaces (draft, testing, custom) if they don't exist.
     *
     * @param indexName The policy index name.
     */
    private void initializeSpaces(String indexName) {
        initializeSpace(indexName, Space.DRAFT.toString(), "Draft policy", "Draft policy");
        initializeSpace(indexName, Space.TEST.toString(), "Test policy", "Test policy");
        initializeSpace(indexName, Space.CUSTOM.toString(), "Custom policy", "Custom policy");
    }

    /**
     * Creates a single space policy document if it does not already exist.
     *
     * @param indexName The index name.
     * @param spaceName The space name.
     * @param title The policy title.
     * @param description The policy description.
     */
    private void initializeSpace(
            String indexName, String spaceName, String title, String description) {
        try {
            // Check if the space document already exists using a search query
            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.termQuery("space.name", spaceName));
            searchSourceBuilder.size(0); // We only care about the count
            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();

            // Proceed only if no document with this space name exists
            if (searchResponse.getHits().getTotalHits().value() == 0) {
                String uuid = UUID.randomUUID().toString();
                String date = LocalDate.now().toString();

                Policy policy = new Policy();
                policy.setId(uuid);
                policy.setTitle(title);
                policy.setDescription(description);
                policy.setAuthor("");
                policy.setRootDecoder("");
                policy.setDocumentation("");
                policy.setIntegrations(Collections.emptyList());
                policy.setReferences(Collections.emptyList());
                policy.setDate(date);
                policy.setModified(date);

                // TODO: Study the model policy and delete the extra fields
                Map<String, Object> docMap = this.mapper.convertValue(policy, Map.class);
                docMap.remove("type"); // Delete the field type inside the document

                String docJson = this.mapper.writeValueAsString(docMap);
                String docHash = HashCalculator.sha256(docJson);

                Map<String, Object> space = new HashMap<>();
                space.put("name", spaceName);
                space.put("hash", Map.of("sha256", docHash));

                Map<String, Object> source = new HashMap<>();
                source.put("document", docMap);
                source.put("space", space);
                // TODO: change to usage of method to calculate space hash
                source.put("hash", Map.of("sha256", docHash));
                source.put("type", "policy");

                IndexRequest request =
                        new IndexRequest(indexName)
                                .id(uuid)
                                .source(this.mapper.writeValueAsString(source), XContentType.JSON)
                                .opType(DocWriteRequest.OpType.CREATE)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                this.client.index(request).actionGet();
            }
        } catch (Exception e) {
            log.error("Failed to initialize space [{}]: {}", spaceName, e.getMessage());
        }
    }
}
